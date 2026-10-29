#!/usr/bin/env python3
"""CISGuard fixed Linux read-only collector v1.0.0; Python 3.11+ required."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

COLLECTOR_VERSION = "0.4.0"
COMMAND_TIMEOUT = 15
MAX_COMMAND_BYTES = 262_144


def now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def source(
    identity: str,
    state: str,
    data: Any = None,
    exit_status: int | None = None,
    error_code: str | None = None,
    limitation: str | None = None,
) -> dict[str, Any]:
    return {
        "source_identity": identity,
        "timestamp": now(),
        "state": state,
        "exit_status": exit_status,
        "data": data,
        "error_code": error_code,
        "limitation": limitation,
    }


def run(command: list[str], *, allowed_nonzero: set[int] | None = None) -> dict[str, Any]:
    executable = shutil.which(command[0])
    if executable is None:
        return {
            "state": "unavailable",
            "exit_status": None,
            "output": None,
            "error_code": "COMMAND_MISSING",
        }
    fixed = [executable, *command[1:]]
    try:
        result = subprocess.run(
            fixed, shell=False, capture_output=True, timeout=COMMAND_TIMEOUT, check=False
        )
    except subprocess.TimeoutExpired:
        return {
            "state": "error",
            "exit_status": None,
            "output": None,
            "error_code": "COMMAND_TIMEOUT",
        }
    output = result.stdout[:MAX_COMMAND_BYTES].decode("utf-8", errors="replace")
    accepted = {0} | (allowed_nonzero or set())
    return {
        "state": "success" if result.returncode in accepted else "error",
        "exit_status": result.returncode,
        "output": output if result.returncode in accepted else None,
        "error_code": None if result.returncode in accepted else "COMMAND_FAILED",
    }


def selected_lines(path: str, patterns: tuple[str, ...]) -> dict[str, Any]:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="strict")
    except FileNotFoundError:
        return {"state": "unavailable", "lines": None, "error_code": "FILE_MISSING"}
    except PermissionError:
        return {"state": "denied", "lines": None, "error_code": "FILE_DENIED"}
    except (OSError, UnicodeError):
        return {"state": "error", "lines": None, "error_code": "FILE_READ_ERROR"}
    expressions = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip()
        and not line.lstrip().startswith("#")
        and any(expression.search(line) for expression in expressions)
    ]
    return {"state": "success", "lines": lines, "error_code": None}


def os_identity() -> dict[str, Any]:
    selected = selected_lines("/etc/os-release", (r"^(ID|VERSION_ID|NAME|PRETTY_NAME)=",))
    if selected["state"] != "success":
        return source("file:/etc/os-release", selected["state"], error_code=selected["error_code"])
    values: dict[str, str] = {}
    for line in selected["lines"]:
        key, value = line.split("=", 1)
        values[key.lower()] = value.strip().strip('"')
    return source("file:/etc/os-release:selected", "success", values, 0)


def ssh_facts() -> dict[str, Any]:
    configured = selected_lines(
        "/etc/ssh/sshd_config",
        (
            r"^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords|"
            r"ClientAliveInterval|ClientAliveCountMax|LoginGraceTime|MaxAuthTries|AllowUsers|AllowGroups|Match)\b",
        ),
    )
    effective = run(["sshd", "-T"])
    state = (
        "success"
        if configured["state"] == "success" or effective["state"] == "success"
        else effective["state"]
    )
    return source(
        "fixed:sshd-config-and-T",
        state,
        {"configured": configured, "effective": effective, "match_context_complete": False}
        if state == "success"
        else None,
        effective["exit_status"],
        effective["error_code"] if state != "success" else None,
        "sshd -T without -C does not represent every Match user/address/host context.",
    )


def file_group(
    identity: str, files: tuple[tuple[str, tuple[str, ...]], ...], limitation: str
) -> dict[str, Any]:
    data = [{"path": path, **selected_lines(path, patterns)} for path, patterns in files]
    states = {item["state"] for item in data}
    state = "success" if "success" in states else "denied" if "denied" in states else "unavailable"
    return source(
        identity,
        state,
        data if state == "success" else None,
        0 if state == "success" else None,
        None if state == "success" else "FILES_UNAVAILABLE",
        limitation,
    )


def service_facts(names: tuple[str, ...]) -> dict[str, Any]:
    if shutil.which("systemctl") is None:
        return source(
            "systemctl:service-allowlist",
            "unavailable",
            error_code="COMMAND_MISSING",
            limitation="Non-systemd service state is not inferred.",
        )
    items = []
    for name in names:
        enabled = run(["systemctl", "is-enabled", name], allowed_nonzero={1, 3, 4})
        active = run(["systemctl", "is-active", name], allowed_nonzero={3, 4})
        items.append({"name": name, "enabled": enabled, "active": active})
    return source(
        "systemctl:service-allowlist",
        "success",
        items,
        0,
        limitation="Enablement and running state are separate.",
    )


def sysctl_facts() -> dict[str, Any]:
    keys = (
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.accept_redirects",
        "net.ipv4.conf.all.send_redirects",
        "kernel.randomize_va_space",
        "fs.protected_hardlinks",
        "fs.protected_symlinks",
    )
    runtime = []
    for key in keys:
        runtime.append({"key": key, **run(["sysctl", "-n", key])})
    configured = []
    for path in ("/etc/sysctl.conf", "/etc/sysctl.d/99-sysctl.conf"):
        configured.append(
            {
                "path": path,
                **selected_lines(path, tuple(r"^\s*" + re.escape(key) + r"\s*=" for key in keys)),
            }
        )
    return source(
        "sysctl:fixed-key-allowlist",
        "success",
        {"configured": configured, "runtime": runtime},
        0,
        limitation="Configured and runtime values are separate.",
    )


def firewall_facts() -> dict[str, Any]:
    commands = {
        "ufw": ["ufw", "status"],
        "firewalld": ["firewall-cmd", "--state"],
        "nftables": ["nft", "list", "ruleset"],
    }
    values = {name: run(command) for name, command in commands.items()}
    if all(item["state"] == "unavailable" for item in values.values()):
        return source(
            "firewall:ufw-firewalld-nftables",
            "unavailable",
            error_code="COMMANDS_MISSING",
            limitation="Missing commands are not treated as disabled firewall state.",
        )
    return source(
        "firewall:ufw-firewalld-nftables",
        "success",
        values,
        0,
        limitation="Configuration/runtime output does not prove effective network exposure.",
    )


def package_facts(distribution: str) -> dict[str, Any]:
    names = (
        "openssh-server",
        "auditd",
        "ufw",
        "firewalld",
        "nftables",
        "libpam-pwquality",
        "libpwquality",
    )
    if distribution == "ubuntu":
        inventory = [
            {"name": name, **run(["dpkg-query", "-W", "-f=${Status} ${Version}", name])}
            for name in names
        ]
        updates = run(["apt", "list", "--upgradable"])
    else:
        inventory = [{"name": name, **run(["rpm", "-q", name])} for name in names]
        updates = run(["dnf", "-q", "--cacheonly", "check-update"], allowed_nonzero={100})
    return source(
        "packages:allowlist-and-cached-updates",
        "success",
        {"inventory": inventory, "cached_updates": updates},
        0,
        limitation="Cached update information is not proof of current patch compliance.",
    )


def permission_facts() -> dict[str, Any]:
    items = []
    for path in ("/etc/passwd", "/etc/group", "/etc/ssh/sshd_config", "/etc/audit/auditd.conf"):
        try:
            info = os.stat(path, follow_symlinks=False)
            items.append(
                {
                    "path": path,
                    "state": "success",
                    "mode": stat.S_IMODE(info.st_mode),
                    "uid": info.st_uid,
                    "gid": info.st_gid,
                }
            )
        except FileNotFoundError:
            items.append(
                {"path": path, "state": "unavailable", "mode": None, "uid": None, "gid": None}
            )
        except PermissionError:
            items.append({"path": path, "state": "denied", "mode": None, "uid": None, "gid": None})
    return source(
        "stat:path-allowlist",
        "success",
        items,
        0,
        limitation="Numeric ownership only; effective access is not inferred.",
    )


def selinux_facts(distribution: str) -> dict[str, Any]:
    if distribution != "rhel":
        return source("selinux:rhel-only", "not_applicable", error_code="NOT_APPLICABLE")
    configured = selected_lines("/etc/selinux/config", (r"^SELINUX=", r"^SELINUXTYPE="))
    runtime = run(["getenforce"])
    state = (
        "success"
        if configured["state"] == "success" or runtime["state"] == "success"
        else "unavailable"
    )
    return source(
        "selinux:config-and-getenforce",
        state,
        {"configured": configured, "runtime": runtime} if state == "success" else None,
        runtime["exit_status"],
        runtime["error_code"] if state != "success" else None,
        "Configured and runtime SELinux modes are separate.",
    )


def main() -> int:
    captured_at = now()
    identity = os_identity()
    distribution = "unknown"
    if identity["state"] == "success":
        distribution = identity["data"].get("id", "unknown")
    sources = {
        "os_identity": identity,
        "ssh": ssh_facts(),
        "pam": file_group(
            "files:pam-allowlist",
            (
                ("/etc/pam.d/common-auth", (r"pam_(faillock|unix|pwquality|pwhistory)",)),
                ("/etc/pam.d/system-auth", (r"pam_(faillock|unix|pwquality|pwhistory)",)),
            ),
            "Selected PAM lines only; included stacks and ordering may require manual review.",
        ),
        "account_policy": file_group(
            "files:account-policy-allowlist",
            (
                ("/etc/login.defs", (r"^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|UMASK)\b",)),
                (
                    "/etc/security/pwquality.conf",
                    (r"^(minlen|dcredit|ucredit|lcredit|ocredit)\s*=",),
                ),
                ("/etc/security/faillock.conf", (r"^(deny|unlock_time|fail_interval)\s*=",)),
            ),
            "Configuration does not prove actual account password strength.",
        ),
        "audit": file_group(
            "files:auditd-allowlist",
            (
                (
                    "/etc/audit/auditd.conf",
                    (
                        r"^(log_file|max_log_file_action|space_left_action|admin_space_left_action)\s*=",
                    ),
                ),
                ("/etc/audit/rules.d/audit.rules", (r"^-",)),
            ),
            "Configured audit files are separate from service runtime state.",
        ),
        "sysctl": sysctl_facts(),
        "firewall": firewall_facts(),
        "services": service_facts(("sshd", "ssh", "auditd", "ufw", "firewalld", "nftables")),
        "packages": package_facts(distribution),
        "permissions": permission_facts(),
        "selinux": selinux_facts(distribution),
    }
    capture = {
        "schema_version": "1.0.0",
        "collector_version": COLLECTOR_VERSION,
        "captured_at": captured_at,
        "sources": sources,
    }
    sys.stdout.write(json.dumps(capture, separators=(",", ":"), sort_keys=True))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# ADR 0003: Honest status, provenance and scores

Status: proposed; source-mandated compliance formula, proposed coverage denominator. References: PRD pp4-5,13; playbook v1.

Technical outcomes are exactly PASS, FAIL, NOT_APPLICABLE, MANUAL_REVIEW, ERROR, NOT_ASSESSED. EXCEPTION is a time-bound approval overlay that never changes the technical result or denominator. Human review produces a separately attributed validation record, not fabricated automated PASS.

Assessed compliance = 100 * PASS / (PASS + FAIL). Coverage proposal = 100 * (PASS + FAIL) / (PASS + FAIL + MANUAL_REVIEW + ERROR + NOT_ASSESSED). Confirmed NOT_APPLICABLE is excluded; unknown applicability remains NOT_ASSESSED/ERROR and stays visible. Percentages round to four decimal places, and zero denominator yields null, never 100 or 0 by invention. Count every selected control in exactly one technical category. Distinct scans/profile versions must not be merged without a declared comparison methodology. The same canonical result store feeds UI and all four exports.

Normalized evidence records exact device, collector and collection versions/method, UTC collection time, capabilities and errors. Fact groups are management, network_policy, os_security and topology. Each fact includes a stable dotted path, typed JSON value, timestamp and evidence IDs. Every fact reference must resolve inside its evidence bundle. Empty evidence is permitted only when there are no observed facts; it cannot support PASS/FAIL.

EvidenceRef includes SHA-256, registered source command/API identity, private encrypted artifact locator and timestamp. Locators describe stored encrypted content, never public URLs or credentials. Offline uploads and fixtures are explicitly labeled. Synthetic examples exercise interfaces only and must never be loaded as live audit results.

All finding inputs preserve benchmark release, profile, policy/evaluator versions, applicability, expected/observed values, severity, evidence and limitations. Unknown support does not imply NOT_APPLICABLE. Unsupported collection returns an explicit error/capability result; report NOT_ASSESSED where no assessment happened, ERROR for failed attempts. Authorized benchmark mappings and source rights must be established before official CIS claims.

Rule operators are allowlisted, bounded and deterministic. No eval, executable YAML tags, unrestricted regex, or arbitrary browser code. Ordered ACL rules must preserve context/order and unsupported semantics must remain visible. Custom rules must be labeled organizational. Compatible SCAP results do not automatically establish complete CIS coverage.

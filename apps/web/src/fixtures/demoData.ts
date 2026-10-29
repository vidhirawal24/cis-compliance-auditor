/**
 * BaselineGuard - Deterministic Synthetic Demo Fixtures
 * 
 * ============================================================================
 * [DEMO - SYNTHETIC DATA]
 * ALL DATA IN THIS FILE IS PURELY SYNTHETIC AND DETERMINISTIC FOR UI DEVELOPMENT.
 * IT DOES NOT REPRESENT REAL DEVICE CREDENTIALS, HOST IDENTITIES, OR LIVE AUDIT
 * FINDINGS. ALL HASHES, ADDRESSES, AND COMMANDS ARE LAB DEMO FIXTURES ONLY.
 * ============================================================================
 */

import {
  EvaluationStatus,
  SeverityLevel,
  PlatformFamily,
  SimulationVerdict,
  ExecutionState,
  UserRole,
  ReportFormat,
} from '../contracts/v1/enums';

import type {
  Organization,
  Asset,
  AssetInterface,
  ScanJob,
  Finding,
  SecurityGraphData,
  RiskScenario,
  RemediationPlan,
  ServiceSafetyContract,
  WhatIfSimulation,
  ApprovalRecord,
  HardeningChange,
  DualVerification,
  ProofPackage,
  GeneratedReport,
  DriftEvent,
  ApplicationAuditEvent,
} from '../contracts/v1/types';

export const DEMO_ORG_ID = 'e9c80d50-1011-42e1-88f2-aa11bb22cc01';

export const DEMO_ORGANIZATION: Organization = {
  org_id: DEMO_ORG_ID,
  name: 'Acme Financial SecOps (DEMO)',
  slug: 'acme-fin-secops-demo',
  created_at: '2026-01-15T08:00:00Z',
  role: UserRole.OWNER,
  is_active: true,
};

// -------------------------------------------------------------
// Synthetic Assets across Heterogeneous Platforms (M01 - M11)
// -------------------------------------------------------------

export const DEMO_ASSETS: Asset[] = [
  {
    asset_id: 'a01-win11-corp-01',
    org_id: DEMO_ORG_ID,
    hostname: 'DEMO-W11-EXEC-01.acme.local',
    primary_ip: '10.100.10.45',
    platform: PlatformFamily.WINDOWS_11,
    vendor: 'Microsoft',
    model: 'Surface Laptop 5',
    os_or_firmware_version: 'Windows 11 Enterprise 23H2 (Build 22631.3007)',
    site: 'HQ-NewYork',
    environment: 'production',
    criticality: 'HIGH',
    tags: ['workstation', 'executive', 'pci-dss'],
    credential_reference_id: 'vault:secret/win11-exec-winrm',
    last_scan_id: 'scan-2026-1029-01',
    last_scan_status: EvaluationStatus.FAIL,
    last_assessed_at: '2026-10-29T10:15:00Z',
    created_at: '2026-02-01T09:00:00Z',
  },
  {
    asset_id: 'a02-win2019-dc-01',
    org_id: DEMO_ORG_ID,
    hostname: 'DEMO-DC01.acme.local',
    primary_ip: '10.100.1.10',
    platform: PlatformFamily.WINDOWS_SERVER_2019,
    vendor: 'Microsoft',
    model: 'Dell PowerEdge R740',
    os_or_firmware_version: 'Windows Server 2019 Standard (1809)',
    site: 'HQ-DataCenter',
    environment: 'production',
    criticality: 'CRITICAL',
    tags: ['domain-controller', 'tier-0', 'identity'],
    credential_reference_id: 'vault:secret/dc01-winrm',
    last_scan_id: 'scan-2026-1029-01',
    last_scan_status: EvaluationStatus.PASS,
    last_assessed_at: '2026-10-29T10:15:00Z',
    created_at: '2026-02-01T09:00:00Z',
  },
  {
    asset_id: 'a03-ubuntu22-app-01',
    org_id: DEMO_ORG_ID,
    hostname: 'DEMO-UBUNTU22-KUBE-01',
    primary_ip: '10.100.20.15',
    platform: PlatformFamily.UBUNTU_22_04,
    vendor: 'Canonical',
    model: 'ProLiant DL380 Gen10',
    os_or_firmware_version: 'Ubuntu 22.04.3 LTS (Kernel 5.15.0-89-generic)',
    site: 'HQ-DataCenter',
    environment: 'production',
    criticality: 'HIGH',
    tags: ['kubernetes', 'linux', 'container-host'],
    credential_reference_id: 'vault:secret/ubuntu-ssh-key',
    last_scan_id: 'scan-2026-1029-01',
    last_scan_status: EvaluationStatus.FAIL,
    last_assessed_at: '2026-10-29T10:15:00Z',
    created_at: '2026-02-01T09:00:00Z',
  },
  {
    asset_id: 'a04-rhel9-db-01',
    org_id: DEMO_ORG_ID,
    hostname: 'DEMO-RHEL9-ORACLE-01',
    primary_ip: '10.100.30.22',
    platform: PlatformFamily.RHEL_9,
    vendor: 'Red Hat',
    model: 'Cisco UCS B200 M5',
    os_or_firmware_version: 'Red Hat Enterprise Linux 9.3 (Plow)',
    site: 'HQ-DataCenter',
    environment: 'production',
    criticality: 'CRITICAL',
    tags: ['database', 'oracle', 'pci-scope'],
    credential_reference_id: 'vault:secret/rhel-ssh-key',
    last_scan_id: 'scan-2026-1029-01',
    last_scan_status: EvaluationStatus.PASS,
    last_assessed_at: '2026-10-29T10:15:00Z',
    created_at: '2026-02-01T09:00:00Z',
  },
  {
    asset_id: 'a05-fortinet-edge-01',
    org_id: DEMO_ORG_ID,
    hostname: 'DEMO-FG100F-PERIMETER',
    primary_ip: '198.51.100.1',
    platform: PlatformFamily.FORTINET_FORTIOS,
    vendor: 'Fortinet',
    model: 'FortiGate 100F',
    os_or_firmware_version: 'FortiOS v7.2.6 build1575',
    site: 'HQ-Edge',
    environment: 'production',
    criticality: 'CRITICAL',
    tags: ['firewall', 'edge', 'perimeter'],
    credential_reference_id: 'vault:secret/fortigate-api-token',
    last_scan_id: 'scan-2026-1029-01',
    last_scan_status: EvaluationStatus.FAIL,
    last_assessed_at: '2026-10-29T10:15:00Z',
    created_at: '2026-02-01T09:00:00Z',
  },
  {
    asset_id: 'a06-cisco-asa-01',
    org_id: DEMO_ORG_ID,
    hostname: 'DEMO-ASA5525-VPN',
    primary_ip: '198.51.100.10',
    platform: PlatformFamily.CISCO_ASA,
    vendor: 'Cisco',
    model: 'ASA 5525-X',
    os_or_firmware_version: 'Cisco Adaptive Security Appliance Software 9.16(2)',
    site: 'HQ-Edge',
    environment: 'production',
    criticality: 'HIGH',
    tags: ['cisco', 'firewall', 'vpn-gateway'],
    credential_reference_id: 'vault:secret/cisco-asa-ssh',
    last_scan_id: 'scan-2026-1029-01',
    last_scan_status: EvaluationStatus.FAIL,
    last_assessed_at: '2026-10-29T10:15:00Z',
    created_at: '2026-02-01T09:00:00Z',
  },
  {
    asset_id: 'a07-checkpoint-gw-01',
    org_id: DEMO_ORG_ID,
    hostname: 'DEMO-CP6600-CLUSTER-A',
    primary_ip: '10.100.0.1',
    platform: PlatformFamily.CHECKPOINT_GAIA,
    vendor: 'Check Point',
    model: 'Quantum Security Gateway 6600',
    os_or_firmware_version: 'Gaia R81.20 Take 631',
    site: 'HQ-DataCenter',
    environment: 'production',
    criticality: 'CRITICAL',
    tags: ['firewall', 'internal-segmentation'],
    credential_reference_id: 'vault:secret/checkpoint-mgmt-api',
    last_scan_id: 'scan-2026-1029-01',
    last_scan_status: EvaluationStatus.PASS,
    last_assessed_at: '2026-10-29T10:15:00Z',
    created_at: '2026-02-01T09:00:00Z',
  },
  {
    asset_id: 'a08-sophos-branch-01',
    org_id: DEMO_ORG_ID,
    hostname: 'DEMO-SOPHOS-XGS2100-BR1',
    primary_ip: '10.200.0.1',
    platform: PlatformFamily.SOPHOS_SFOS,
    vendor: 'Sophos',
    model: 'XGS 2100',
    os_or_firmware_version: 'SFOS 20.0.0 GA-Build222',
    site: 'Branch-London',
    environment: 'production',
    criticality: 'MEDIUM',
    tags: ['sophos', 'branch', 'sd-wan'],
    credential_reference_id: 'vault:secret/sophos-rest-api',
    last_scan_id: 'scan-2026-1029-01',
    last_scan_status: EvaluationStatus.FAIL,
    last_assessed_at: '2026-10-29T10:15:00Z',
    created_at: '2026-02-01T09:00:00Z',
  },
  {
    asset_id: 'a09-paloalto-panos-01',
    org_id: DEMO_ORG_ID,
    hostname: 'DEMO-PA3260-DMZ',
    primary_ip: '10.100.50.1',
    platform: PlatformFamily.PALO_ALTO_PANOS,
    vendor: 'Palo Alto Networks',
    model: 'PA-3260',
    os_or_firmware_version: 'PAN-OS 11.0.2-h3',
    site: 'HQ-DataCenter',
    environment: 'production',
    criticality: 'CRITICAL',
    tags: ['firewall', 'dmz', 'ngfw'],
    credential_reference_id: 'vault:secret/panos-xml-api',
    last_scan_id: 'scan-2026-1029-01',
    last_scan_status: EvaluationStatus.PASS,
    last_assessed_at: '2026-10-29T10:15:00Z',
    created_at: '2026-02-01T09:00:00Z',
  },
  {
    asset_id: 'a10-cisco-core-router-01',
    org_id: DEMO_ORG_ID,
    hostname: 'DEMO-ASR1001X-WAN',
    primary_ip: '198.51.100.254',
    platform: PlatformFamily.CISCO_IOS_ROUTER,
    vendor: 'Cisco',
    model: 'ASR 1001-X',
    os_or_firmware_version: 'Cisco IOS-XE 17.09.04a',
    site: 'HQ-Edge',
    environment: 'production',
    criticality: 'CRITICAL',
    tags: ['router', 'wan', 'bgp'],
    credential_reference_id: 'vault:secret/cisco-router-ssh',
    last_scan_id: 'scan-2026-1029-01',
    last_scan_status: EvaluationStatus.FAIL,
    last_assessed_at: '2026-10-29T10:15:00Z',
    created_at: '2026-02-01T09:00:00Z',
  },
  {
    asset_id: 'a11-cisco-core-switch-01',
    org_id: DEMO_ORG_ID,
    hostname: 'DEMO-CAT9300-DIST-01',
    primary_ip: '10.100.0.10',
    platform: PlatformFamily.CISCO_IOS_SWITCH,
    vendor: 'Cisco',
    model: 'Catalyst 9300-48P',
    os_or_firmware_version: 'Cisco IOS-XE 17.09.03a',
    site: 'HQ-Campus',
    environment: 'production',
    criticality: 'HIGH',
    tags: ['switch', 'access-layer', 'layer2'],
    credential_reference_id: 'vault:secret/cisco-switch-ssh',
    last_scan_id: 'scan-2026-1029-01',
    last_scan_status: EvaluationStatus.FAIL,
    last_assessed_at: '2026-10-29T10:15:00Z',
    created_at: '2026-02-01T09:00:00Z',
  },
];

// -------------------------------------------------------------
// Switch Interfaces Fixture (M11, M26, M27, M28, M29, M30)
// -------------------------------------------------------------

export const DEMO_SWITCH_INTERFACES: AssetInterface[] = [
  {
    interface_id: 'int-g1-0-1',
    name: 'GigabitEthernet1/0/1',
    mac_address: '00:62:EC:A1:01:01',
    ipv4_address: '10.100.10.1',
    vlan_id: 1, // Violates M30: Management traffic on VLAN 1
    is_management: true,
    port_security_enabled: false, // Violates M27: Port security disabled
    is_unused_disabled: false, // Violates M26: Unused port enabled
  },
  {
    interface_id: 'int-g1-0-2',
    name: 'GigabitEthernet1/0/2',
    mac_address: '00:62:EC:A1:01:02',
    vlan_id: 10,
    is_management: false,
    port_security_enabled: true,
    max_mac_count: 2,
    is_unused_disabled: true,
  },
  {
    interface_id: 'int-g1-0-3',
    name: 'GigabitEthernet1/0/3',
    mac_address: '00:62:EC:A1:01:03',
    vlan_id: 20,
    is_management: false,
    port_security_enabled: false,
    is_unused_disabled: false, // Violates M26: Unused switch port not disabled
  },
];

// -------------------------------------------------------------
// Scan Jobs & Invariant Scores (M13, M34, M35, E04, E08, E18)
// -------------------------------------------------------------

export const DEMO_SCANS: ScanJob[] = [
  {
    scan_id: 'scan-2026-1029-01',
    org_id: DEMO_ORG_ID,
    status: 'COMPLETED',
    read_only: true, // Invariant: Scan is strictly read-only
    requested_assets: 11,
    completed_assets: 11,
    failed_assets: 0,
    // Scoring Invariant: PASS / (PASS + FAIL) * 100
    // 32 PASS, 12 FAIL => 32 / (32 + 12) = 72.7%
    assessed_compliance_pct: 72.7,
    // Coverage Invariant: (PASS + FAIL) / Total Applicable * 100
    // (44 assessed / 52 total applicable) = 84.6%
    assessment_coverage_pct: 84.6,
    policy_pack_id: 'cis-multi-platform-v1',
    profile_level: 'LEVEL_1',
    target_asset_ids: DEMO_ASSETS.map((a) => a.asset_id),
    started_at: '2026-10-29T10:00:00Z',
    completed_at: '2026-10-29T10:14:32Z',
    trigger_type: 'MANUAL',
  },
  {
    scan_id: 'scan-2026-1028-02',
    org_id: DEMO_ORG_ID,
    status: 'COMPLETED',
    read_only: true,
    requested_assets: 11,
    completed_assets: 11,
    failed_assets: 0,
    assessed_compliance_pct: 69.8,
    assessment_coverage_pct: 82.0,
    policy_pack_id: 'cis-multi-platform-v1',
    profile_level: 'LEVEL_1',
    target_asset_ids: DEMO_ASSETS.map((a) => a.asset_id),
    started_at: '2026-10-28T02:00:00Z',
    completed_at: '2026-10-28T02:15:10Z',
    trigger_type: 'SCHEDULED',
  },
];

// -------------------------------------------------------------
// Findings with Evidence & Expected vs Actual (M16, M20 - M33, M36, M37)
// -------------------------------------------------------------

export const DEMO_FINDINGS: Finding[] = [
  {
    finding_id: 'find-telnet-01',
    org_id: DEMO_ORG_ID,
    asset_id: 'a10-cisco-core-router-01',
    scan_id: 'scan-2026-1029-01',
    control_id: 'CIS-CISCO-ROUTER-2.1.1',
    benchmark_pack_id: 'cis-cisco-ios-benchmark-v4',
    profile_level: 'LEVEL_1',
    title: 'Management Plane Telnet Service Enabled (M20)',
    category: 'Management Plane Security',
    severity: SeverityLevel.CRITICAL,
    status: EvaluationStatus.FAIL,
    expected_state: {
      'line.vty.transport_input': ['ssh'],
      'service.telnet_enabled': false,
    },
    observed_state: {
      'line.vty.transport_input': ['telnet', 'ssh'],
      'service.telnet_enabled': true,
    },
    evidence_ref: {
      sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      source_command: 'show running-config | section line vty',
      artifact_uri: 'supabase://audit-evidence/2026-10-29/a10_vty_config.txt.enc',
      timestamp: '2026-10-29T10:02:11Z',
    },
    remediation_cli: `configure terminal\nline vty 0 4\n transport input ssh\n exec-timeout 10 0\nexit\nwrite memory`,
    remediation_prerequisites: ['Ensure SSH keys are generated via crypto key generate rsa modulus 2048', 'Verify SSH connectivity before disconnecting current session'],
    remediation_risk_warning: 'Changing transport input from telnet to ssh may lock out administrators if SSH is misconfigured.',
    requires_manual_review: false,
    evaluated_at: '2026-10-29T10:02:15Z',
  },
  {
    finding_id: 'find-acl-permissive-02',
    org_id: DEMO_ORG_ID,
    asset_id: 'a06-cisco-asa-01',
    scan_id: 'scan-2026-1029-01',
    control_id: 'CIS-CISCO-ASA-1.3.4',
    benchmark_pack_id: 'cis-cisco-asa-benchmark-v3',
    profile_level: 'LEVEL_1',
    title: 'Over-Permissive Inbound Access List Entry Detected (M22, M23)',
    category: 'Network Policy & Firewalls',
    severity: SeverityLevel.CRITICAL,
    status: EvaluationStatus.FAIL,
    expected_state: {
      'acl.inbound_outside.permit_any_any': false,
      'acl.restricted_ports.22': 'scoped_subnets_only',
    },
    observed_state: {
      'acl.inbound_outside.permit_any_any': true,
      'rule_raw': 'access-list OUTSIDE_IN extended permit ip any any',
      'line_number': 42,
    },
    evidence_ref: {
      sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
      source_command: 'show running-config access-list OUTSIDE_IN',
      artifact_uri: 'supabase://audit-evidence/2026-10-29/a06_acl_outside.txt.enc',
      timestamp: '2026-10-29T10:04:18Z',
    },
    remediation_cli: `no access-list OUTSIDE_IN extended permit ip any any\naccess-list OUTSIDE_IN extended permit tcp host 198.51.100.50 host 10.100.20.15 eq 443`,
    remediation_prerequisites: ['Audit business partner public IP whitelist', 'Review Batfish reachability simulation prior to applying change'],
    remediation_risk_warning: 'Removing wildcard permit will drop unauthorized traffic. Verify legitimate external flows first.',
    requires_manual_review: false,
    evaluated_at: '2026-10-29T10:04:22Z',
  },
  {
    finding_id: 'find-shadowed-rule-03',
    org_id: DEMO_ORG_ID,
    asset_id: 'a05-fortinet-edge-01',
    scan_id: 'scan-2026-1029-01',
    control_id: 'CIS-FORTINET-2.4.1',
    benchmark_pack_id: 'cis-fortigate-benchmark-v2',
    profile_level: 'LEVEL_1',
    title: 'Fully Shadowed Firewall Security Policy (M24)',
    category: 'Network Policy & Firewalls',
    severity: SeverityLevel.MEDIUM,
    status: EvaluationStatus.FAIL,
    expected_state: {
      'policy.rule_id_104.is_shadowed': false,
    },
    observed_state: {
      'policy.rule_id_104.is_shadowed': true,
      'shadowed_by_rule_id': 102,
      'conflict_reason': 'Rule 102 permits 10.100.0.0/16 to ANY before Rule 104 can evaluate 10.100.20.0/24',
    },
    evidence_ref: {
      sha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
      source_command: 'get firewall policy 104',
      artifact_uri: 'supabase://audit-evidence/2026-10-29/a05_policy_rules.json.enc',
      timestamp: '2026-10-29T10:05:40Z',
    },
    remediation_cli: `config firewall policy\n move 104 before 102\nend`,
    remediation_risk_warning: 'Reordering policies modifies first-match evaluation order.',
    requires_manual_review: false,
    evaluated_at: '2026-10-29T10:05:45Z',
  },
  {
    finding_id: 'find-vlan1-switch-04',
    org_id: DEMO_ORG_ID,
    asset_id: 'a11-cisco-core-switch-01',
    scan_id: 'scan-2026-1029-01',
    control_id: 'CIS-CISCO-SWITCH-1.1.2',
    benchmark_pack_id: 'cis-cisco-switch-benchmark-v3',
    profile_level: 'LEVEL_1',
    title: 'Native VLAN 1 Used for Management Traffic (M30)',
    category: 'Layer 2 Switching',
    severity: SeverityLevel.HIGH,
    status: EvaluationStatus.FAIL,
    expected_state: {
      'vlan.management_vlan_id': 99,
      'vlan.default_vlan_1_active': false,
    },
    observed_state: {
      'vlan.management_vlan_id': 1,
      'vlan.default_vlan_1_active': true,
    },
    evidence_ref: {
      sha256: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
      source_command: 'show interface vlan 1',
      artifact_uri: 'supabase://audit-evidence/2026-10-29/a11_vlan1.txt.enc',
      timestamp: '2026-10-29T10:07:01Z',
    },
    remediation_cli: `configure terminal\nvlan 99\n name MGMT_ISOLATED\ninterface Vlan99\n ip address 10.100.99.10 255.255.255.0\n no shutdown\ninterface Vlan1\n shutdown\n no ip address\nexit`,
    remediation_prerequisites: ['Trunk VLAN 99 across all distribution switches before shutting down VLAN 1'],
    remediation_risk_warning: 'Immediate management loss if trunking or routing for VLAN 99 is not established prior to executing shutdown.',
    requires_manual_review: false,
    evaluated_at: '2026-10-29T10:07:05Z',
  },
  {
    finding_id: 'find-ssh-root-login-05',
    org_id: DEMO_ORG_ID,
    asset_id: 'a03-ubuntu22-app-01',
    scan_id: 'scan-2026-1029-01',
    control_id: 'CIS-UBUNTU-5.2.10',
    benchmark_pack_id: 'cis-ubuntu-linux-benchmark-v2',
    profile_level: 'LEVEL_1',
    title: 'SSH PermitRootLogin Set to Yes (M03, M21)',
    category: 'OS Access & Authentication',
    severity: SeverityLevel.HIGH,
    status: EvaluationStatus.FAIL,
    expected_state: {
      'sshd_config.PermitRootLogin': 'no',
    },
    observed_state: {
      'sshd_config.PermitRootLogin': 'yes',
    },
    evidence_ref: {
      sha256: 'a127f87f2b1860824b0811b3bc5c8680d96d9ccca9ef0934f8d4fa969f67a7b8',
      source_command: 'grep -E "^PermitRootLogin" /etc/ssh/sshd_config',
      artifact_uri: 'supabase://audit-evidence/2026-10-29/a03_sshd_config.txt.enc',
      timestamp: '2026-10-29T10:09:12Z',
    },
    remediation_cli: `sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config\nsystemctl restart sshd`,
    remediation_prerequisites: ['Ensure at least one sudo-capable administrative user is provisioned'],
    remediation_risk_warning: 'Ensure authorized operator has active sudo credentials before restarting sshd.',
    requires_manual_review: false,
    evaluated_at: '2026-10-29T10:09:18Z',
  },
  {
    finding_id: 'find-physical-security-06',
    org_id: DEMO_ORG_ID,
    asset_id: 'a02-win2019-dc-01',
    scan_id: 'scan-2026-1029-01',
    control_id: 'CIS-WIN2019-1.1.1',
    benchmark_pack_id: 'cis-windows-server-2019-benchmark-v3',
    profile_level: 'LEVEL_1',
    title: 'Physical Console Enclosure & Access Locks (E12)',
    category: 'Physical Security',
    severity: SeverityLevel.LOW,
    status: EvaluationStatus.MANUAL_REVIEW, // Human review required
    expected_state: {
      'datacenter_rack_lock': 'active_badge_controlled',
    },
    observed_state: {
      'human_attestation': 'pending_inspector_sign_off',
    },
    evidence_ref: {
      sha256: 'b14a7b8059d9f0e7928dc3ab9f85bf7184c13f201d41647f48d206c1657e33e3',
      source_command: 'manual_verification_ticket_7741',
      artifact_uri: 'supabase://audit-evidence/manual/ticket_7741_photo.jpg.enc',
      timestamp: '2026-10-29T10:10:00Z',
    },
    requires_manual_review: true,
    evaluated_at: '2026-10-29T10:10:05Z',
  },
  {
    finding_id: 'find-win11-uac-07',
    org_id: DEMO_ORG_ID,
    asset_id: 'a01-win11-corp-01',
    scan_id: 'scan-2026-1029-01',
    control_id: 'CIS-WIN11-2.3.17',
    benchmark_pack_id: 'cis-windows-11-benchmark-v3',
    profile_level: 'LEVEL_1',
    title: 'User Account Control: Behavior of the elevation prompt for administrators (M01)',
    category: 'Local Policies & Options',
    severity: SeverityLevel.HIGH,
    status: EvaluationStatus.FAIL,
    expected_state: {
      'registry.ConsentPromptBehaviorAdmin': 2,
    },
    observed_state: {
      'registry.ConsentPromptBehaviorAdmin': 0, // Elevate without prompting
    },
    evidence_ref: {
      sha256: 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2',
      source_command: 'Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "ConsentPromptBehaviorAdmin"',
      artifact_uri: 'supabase://audit-evidence/2026-10-29/a01_uac_reg.json.enc',
      timestamp: '2026-10-29T10:11:45Z',
    },
    // Approved exception active for Executive device until Nov 30, 2026 (E14)
    exception: {
      exception_id: 'exc-2026-901',
      reason: 'Legacy automated deployment software compatibility in C-suite suite',
      approver_email: 'ciso@acmefinancial.com',
      approved_at: '2026-10-01T12:00:00Z',
      expires_at: '2026-11-30T23:59:59Z',
      is_expired: false,
    },
    remediation_cli: `Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "ConsentPromptBehaviorAdmin" -Value 2`,
    requires_manual_review: false,
    evaluated_at: '2026-10-29T10:11:50Z',
  },
];

// -------------------------------------------------------------
// Interactive Cytoscape Graph Data (I01, I03, I05)
// -------------------------------------------------------------

export const DEMO_SECURITY_GRAPH: SecurityGraphData = {
  nodes: [
    { data: { id: 'ext-inet', label: 'Untrusted Internet', type: 'subnet', cidr: '0.0.0.0/0' } },
    { data: { id: 'a05', label: 'DEMO-FG100F (Edge)', type: 'asset', platform: PlatformFamily.FORTINET_FORTIOS, ip_address: '198.51.100.1' } },
    { data: { id: 'a06', label: 'DEMO-ASA-VPN', type: 'asset', platform: PlatformFamily.CISCO_ASA, ip_address: '198.51.100.10' } },
    { data: { id: 'a10', label: 'DEMO-ASR-WAN', type: 'asset', platform: PlatformFamily.CISCO_IOS_ROUTER, ip_address: '198.51.100.254' } },
    { data: { id: 'a11', label: 'DEMO-CAT9300-DIST', type: 'asset', platform: PlatformFamily.CISCO_IOS_SWITCH, ip_address: '10.100.0.10' } },
    { data: { id: 'a03', label: 'DEMO-UBUNTU-APP', type: 'asset', platform: PlatformFamily.UBUNTU_22_04, ip_address: '10.100.20.15' } },
    { data: { id: 'f-telnet', label: 'M20: Telnet Active', type: 'finding', severity: SeverityLevel.CRITICAL, status: EvaluationStatus.FAIL } },
    { data: { id: 'f-acl', label: 'M22: Permit Any Any', type: 'finding', severity: SeverityLevel.CRITICAL, status: EvaluationStatus.FAIL } },
    { data: { id: 'f-vlan1', label: 'M30: VLAN 1 Mgmt', type: 'finding', severity: SeverityLevel.HIGH, status: EvaluationStatus.FAIL } },
    { data: { id: 'f-root', label: 'M03: Root SSH', type: 'finding', severity: SeverityLevel.HIGH, status: EvaluationStatus.FAIL } },
  ],
  edges: [
    { data: { id: 'e1', source: 'ext-inet', target: 'a06', relation: 'routes_to', confidence: 'CONFIRMED' } },
    { data: { id: 'e2', source: 'a06', target: 'f-acl', relation: 'violates', confidence: 'CONFIRMED' } },
    { data: { id: 'e3', source: 'a06', target: 'a10', relation: 'allows', confidence: 'CONFIRMED' } },
    { data: { id: 'e4', source: 'a10', target: 'f-telnet', relation: 'violates', confidence: 'CONFIRMED' } },
    { data: { id: 'e5', source: 'a10', target: 'a11', relation: 'routes_to', confidence: 'CONFIRMED' } },
    { data: { id: 'e6', source: 'a11', target: 'f-vlan1', relation: 'violates', confidence: 'CONFIRMED' } },
    { data: { id: 'e7', source: 'a11', target: 'a03', relation: 'attached_to', confidence: 'CONFIRMED' } },
    { data: { id: 'e8', source: 'a03', target: 'f-root', relation: 'violates', confidence: 'CONFIRMED' } },
  ],
  meta: {
    total_nodes: 10,
    total_edges: 8,
    coverage_completeness_pct: 95.0,
  },
};

// -------------------------------------------------------------
// Correlated Risk Scenarios (I02, I04, I05)
// -------------------------------------------------------------

export const DEMO_RISK_SCENARIOS: RiskScenario[] = [
  {
    scenario_id: 'scen-01-perimeter-pivot',
    org_id: DEMO_ORG_ID,
    title: 'Cross-Device Attack Chain: Inbound Perimeter Bypass to Internal App Host',
    description: 'Permissive firewall ACL (M22) exposes edge router telnet management port (M20). Combined with default VLAN 1 trunking (M30), an unauthenticated attacker can sniff internal traffic and attempt brute force against root SSH (M03).',
    severity: SeverityLevel.CRITICAL,
    risk_score: 94,
    source_finding_ids: ['find-acl-permissive-02', 'find-telnet-01', 'find-vlan1-switch-04', 'find-ssh-root-login-05'],
    affected_asset_ids: ['a06-cisco-asa-01', 'a10-cisco-core-router-01', 'a11-cisco-core-switch-01', 'a03-ubuntu22-app-01'],
    causal_chain: [
      'Inbound traffic permitted via ASA wildcard ACL',
      'Plaintext Telnet credentials sniffable across management subnet',
      'VLAN 1 broadcast domain allows Layer-2 hop hopping to app server',
      'Direct root login enabled on Ubuntu application server',
    ],
    confidence_pct: 92,
    business_impact: 'High risk of complete core network takeover and lateral movement into PCI-DSS scoped databases.',
  },
];

// -------------------------------------------------------------
// Remediation Plan & OR-Tools Optimization (I06, I07, I08, I10)
// -------------------------------------------------------------

export const DEMO_REMEDIATION_PLAN: RemediationPlan = {
  plan_id: 'plan-2026-8801',
  org_id: DEMO_ORG_ID,
  state: ExecutionState.SIMULATED,
  plan_hash: '9a3f2b84e1b80c10294e5b61e2f801659a7d32c10b9911e2478a104523bc7891',
  target_asset_ids: ['a10-cisco-core-router-01', 'a06-cisco-asa-01', 'a03-ubuntu22-app-01'],
  minimal_change_score: 18.5, // OR-Tools CP-SAT minimal disruption score
  conflict_detected: false,
  conflicts: [],
  actions: [
    {
      action_id: 'act-01-telnet',
      asset_id: 'a10-cisco-core-router-01',
      vendor: 'Cisco',
      title: 'Disable Telnet and enforce SSHv2 on VTY lines (M20, M21)',
      command_template: 'line vty 0 4\n transport input ssh\n exec-timeout 10 0',
      sequence_order: 1, // Change sequencing (I10) ensures management access before firewall lock down
      risk_weight: 4.2,
      is_reversible: true,
      recovery_plan: 'Rollback VTY transport to allow telnet via console cable if SSH fails.',
      prerequisites: ['Crypto RSA 2048 keys verified on router', 'Administrative workstation IP in trusted subnet'],
      status: 'PENDING',
    },
    {
      action_id: 'act-02-acl',
      asset_id: 'a06-cisco-asa-01',
      vendor: 'Cisco',
      title: 'Restrict Inbound Outside ACL to specific HTTPS endpoints (M22, M23)',
      command_template: 'no access-list OUTSIDE_IN extended permit ip any any\naccess-list OUTSIDE_IN extended permit tcp host 198.51.100.50 host 10.100.20.15 eq 443',
      sequence_order: 2,
      risk_weight: 6.8,
      is_reversible: true,
      recovery_plan: 'Re-insert prior permit entry from pre-change snapshot backup.',
      prerequisites: ['Step 1 verified complete', 'Safety Contract SC-01 satisfied'],
      status: 'PENDING',
    },
    {
      action_id: 'act-03-ssh',
      asset_id: 'a03-ubuntu22-app-01',
      vendor: 'Canonical',
      title: 'Disable Root SSH Login on Ubuntu App Server (M03)',
      command_template: "sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload sshd",
      sequence_order: 3,
      risk_weight: 3.5,
      is_reversible: true,
      recovery_plan: 'Re-enable PermitRootLogin via local console / KVM session.',
      prerequisites: ['Admin account "secadmin" verified in sudoers group'],
      status: 'PENDING',
    },
  ],
  created_at: '2026-10-29T11:00:00Z',
};

// -------------------------------------------------------------
// Service-Safety Contracts (I12) & What-If Simulation (I11, I13, I14)
// -------------------------------------------------------------

export const DEMO_SAFETY_CONTRACTS: ServiceSafetyContract[] = [
  {
    contract_id: 'sc-01-mgmt-access',
    org_id: DEMO_ORG_ID,
    name: 'Preserve Admin Subnet to Core Management Reachability',
    description: 'Mandatory contract: Hardening changes must never sever administrative SSH access from SecOps subnet 10.100.100.0/24 to any router or switch.',
    source_cidr: '10.100.100.0/24',
    destination_cidr: '10.100.0.0/16',
    port_range: '22',
    protocol: 'TCP',
    mandatory: true, // Blocks approval if violated (I14)
    active: true,
  },
  {
    contract_id: 'sc-02-app-https',
    org_id: DEMO_ORG_ID,
    name: 'Public Ingress to Kubernetes Ingress Gateway (443/TCP)',
    description: 'Preserves external client access to web application tier.',
    source_cidr: '0.0.0.0/0',
    destination_cidr: '10.100.20.15/32',
    port_range: '443',
    protocol: 'TCP',
    mandatory: true,
    active: true,
  },
];

export const DEMO_WHAT_IF_SIMULATION: WhatIfSimulation = {
  simulation_id: 'sim-2026-4401',
  plan_id: 'plan-2026-8801',
  verdict: SimulationVerdict.SAFE_IN_MODEL,
  model_engine: 'BATFISH',
  model_coverage_pct: 91.5,
  safety_contracts_evaluated: 2,
  safety_contracts_violated: 0,
  affected_services: ['22/tcp (SSH)', '23/tcp (Telnet - BLOCKED)', '443/tcp (HTTPS - PRESERVED)'],
  blast_radius_asset_count: 3,
  created_at: '2026-10-29T11:15:00Z',
};

// -------------------------------------------------------------
// Approval & Controlled Hardening Execution (E23, E21, I15)
// -------------------------------------------------------------

export const DEMO_APPROVAL_RECORD: ApprovalRecord = {
  approval_id: 'appr-2026-001',
  plan_id: 'plan-2026-8801',
  plan_hash: '9a3f2b84e1b80c10294e5b61e2f801659a7d32c10b9911e2478a104523bc7891',
  approver_id: 'usr-ciso-01',
  approver_email: 'ciso@acmefinancial.com',
  operator_id: 'usr-secops-02', // Separation of Duties verified: operator != approver
  justification: 'Vetted minimal-change plan eliminates perimeter exposure without violating SC-01.',
  safety_contracts_passed: true,
  backup_readiness_confirmed: true,
  status: 'APPROVED',
  approved_at: '2026-10-29T11:30:00Z',
};

export const DEMO_HARDENING_CHANGE: HardeningChange = {
  change_id: 'chg-2026-7701',
  plan_id: 'plan-2026-8801',
  state: ExecutionState.VERIFIED,
  current_stage_batch: 2,
  total_stage_batches: 2,
  backup_snapshot_hash: '7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b',
  canary_halt_triggered: false,
  execution_events: [
    { timestamp: '2026-10-29T11:35:00Z', stage: 'PRECHECK', status: 'SUCCESS', message: 'Pre-flight connection and credential validation succeeded.' },
    { timestamp: '2026-10-29T11:35:10Z', stage: 'BACKUP', status: 'SUCCESS', message: 'Encrypted snapshot saved to OpenBao vault and Supabase storage.' },
    { timestamp: '2026-10-29T11:36:00Z', stage: 'STAGE_1_CANARY', status: 'SUCCESS', message: 'Applied router VTY hardening on a10. Management connection verified intact.' },
    { timestamp: '2026-10-29T11:37:00Z', stage: 'STAGE_2_PRODUCTION', status: 'SUCCESS', message: 'Applied ASA ACL restricted policy and Ubuntu sshd config.' },
    { timestamp: '2026-10-29T11:38:00Z', stage: 'POST_CHECK', status: 'SUCCESS', message: 'Triggered automated dual-verification re-audit.' },
  ],
};

// -------------------------------------------------------------
// Dual Verification & Cryptographic Proof Dossier (I16, I17, I18)
// -------------------------------------------------------------

export const DEMO_DUAL_VERIFICATION: DualVerification = {
  verification_id: 'verif-2026-9901',
  change_id: 'chg-2026-7701',
  cis_control_status: EvaluationStatus.PASS, // Re-evaluated CIS control passed
  service_probe_status: EvaluationStatus.PASS, // Live reachability check on 443 passed
  overall_verified: true, // Both checks passed
  pre_change_risk_score: 94,
  residual_risk_score: 12, // Residual risk reduced from 94 to 12
  verified_at: '2026-10-29T11:39:15Z',
};

export const DEMO_PROOF_PACKAGE: ProofPackage = {
  package_id: 'proof-2026-001',
  change_id: 'chg-2026-7701',
  org_id: DEMO_ORG_ID,
  digital_signature: 'MEQCIGv...DEMO_ECDSA_SHA256_SIGNATURE...78aBcDeFgHiJkLmNoPqRsTuVwXyZ==',
  signer_identity: 'BaselineGuard-Hardening-Orchestrator-v1',
  pre_hardening_config_hash: '7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b',
  post_hardening_config_hash: '3f7a1b9c2d4e6f8a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a',
  execution_log_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  manifest_verified: true,
  created_at: '2026-10-29T11:40:00Z',
  download_urls: {
    pdf: 'https://demo-storage.baselineguard.local/proof-packages/proof-2026-001.pdf',
    json: 'https://demo-storage.baselineguard.local/proof-packages/proof-2026-001.json',
  },
};

// -------------------------------------------------------------
// Drift Events, Reports & Application Audit Trail (E05, E19, M38)
// -------------------------------------------------------------

export const DEMO_DRIFT_EVENTS: DriftEvent[] = [
  {
    event_id: 'drift-01',
    org_id: DEMO_ORG_ID,
    asset_id: 'a05-fortinet-edge-01',
    hostname: 'DEMO-FG100F-PERIMETER',
    detected_at: '2026-10-29T08:14:00Z',
    severity: SeverityLevel.MEDIUM,
    diff_preview: `--- baseline/policy.conf\n+++ observed/policy.conf\n@@ -45,3 +45,4 @@\n edit 104\n+ set status enable\n next`,
    previous_snapshot_id: 'snap-2026-1020-01',
    current_snapshot_id: 'snap-2026-1029-01',
  },
];

export const DEMO_REPORTS: GeneratedReport[] = [
  {
    report_id: 'rep-01-executive',
    org_id: DEMO_ORG_ID,
    title: 'BaselineGuard Executive Posture & Compliance Report (Q4)',
    format: ReportFormat.PDF,
    file_size_bytes: 2485120,
    download_url: 'https://demo-storage.baselineguard.local/reports/rep-01-executive.pdf',
    signed_url_expires_at: '2026-10-30T10:00:00Z',
    created_at: '2026-10-29T10:30:00Z',
  },
  {
    report_id: 'rep-02-technical',
    org_id: DEMO_ORG_ID,
    title: 'Detailed Technical Finding Export (All Platforms)',
    format: ReportFormat.JSON,
    file_size_bytes: 842100,
    download_url: 'https://demo-storage.baselineguard.local/reports/rep-02-technical.json',
    signed_url_expires_at: '2026-10-30T10:00:00Z',
    created_at: '2026-10-29T10:31:00Z',
  },
];

export const DEMO_AUDIT_TRAIL: ApplicationAuditEvent[] = [
  {
    event_id: 'audit-evt-01',
    org_id: DEMO_ORG_ID,
    actor_id: 'usr-secops-02',
    actor_email: 'operator@acmefinancial.com',
    action_type: 'AUDIT_SCAN_LAUNCH',
    target_resource_id: 'scan-2026-1029-01',
    timestamp: '2026-10-29T10:00:00Z',
    ip_address: '10.100.100.44',
    sha256_hash: '8f4c2b9...a10b',
  },
  {
    event_id: 'audit-evt-02',
    org_id: DEMO_ORG_ID,
    actor_id: 'usr-ciso-01',
    actor_email: 'ciso@acmefinancial.com',
    action_type: 'REMEDIATION_PLAN_APPROVED',
    target_resource_id: 'plan-2026-8801',
    timestamp: '2026-10-29T11:30:00Z',
    ip_address: '10.100.100.12',
    sha256_hash: '9a3f2b8...7891',
  },
];


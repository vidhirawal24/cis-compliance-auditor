/**
 * BaselineGuard - Frozen Contract v1.0.0 Enums
 * Source: Playbook v1.0 & PRD v1.0
 * Strict deterministic enums - No client-side modification
 */

export enum EvaluationStatus {
  PASS = 'PASS',
  FAIL = 'FAIL',
  NOT_APPLICABLE = 'NOT_APPLICABLE',
  MANUAL_REVIEW = 'MANUAL_REVIEW',
  ERROR = 'ERROR',
  NOT_ASSESSED = 'NOT_ASSESSED',
}

export enum SeverityLevel {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INFORMATIONAL = 'INFORMATIONAL',
}

export enum PlatformFamily {
  WINDOWS_11 = 'windows_11',
  WINDOWS_SERVER_2019 = 'windows_server_2019',
  UBUNTU_20_04 = 'ubuntu_20_04',
  UBUNTU_22_04 = 'ubuntu_22_04',
  RHEL_8 = 'rhel_8',
  RHEL_9 = 'rhel_9',
  FORTINET_FORTIOS = 'fortinet_fortios',
  CISCO_ASA = 'cisco_asa',
  CISCO_FTD = 'cisco_ftd',
  CHECKPOINT_GAIA = 'checkpoint_gaia',
  SOPHOS_SFOS = 'sophos_sfos',
  PALO_ALTO_PANOS = 'palo_alto_panos',
  CISCO_IOS_ROUTER = 'cisco_ios_router',
  CISCO_IOS_SWITCH = 'cisco_ios_switch',
}

export enum SimulationVerdict {
  SAFE_IN_MODEL = 'SAFE_IN_MODEL',
  VIOLATES_CONTRACT = 'VIOLATES_CONTRACT',
  UNSUPPORTED = 'UNSUPPORTED',
  INSUFFICIENT_EVIDENCE = 'INSUFFICIENT_EVIDENCE',
}

export enum ExecutionState {
  DRAFT = 'DRAFT',
  SIMULATED = 'SIMULATED',
  PRECHECKED = 'PRECHECKED',
  PENDING_APPROVAL = 'PENDING_APPROVAL',
  APPROVED = 'APPROVED',
  EXECUTING = 'EXECUTING',
  VERIFYING = 'VERIFYING',
  VERIFIED = 'VERIFIED',
  FAILED = 'FAILED',
  ROLLED_BACK = 'ROLLED_BACK',
  NEEDS_MANUAL_RECOVERY = 'NEEDS_MANUAL_RECOVERY',
}

export enum UserRole {
  OWNER = 'OWNER',
  ADMIN = 'ADMIN',
  APPROVER = 'APPROVER',
  OPERATOR = 'OPERATOR',
  AUDITOR = 'AUDITOR',
  VIEWER = 'VIEWER',
}

export enum CollectionMethod {
  SSH = 'ssh',
  WINRM = 'winrm',
  REST_API = 'rest_api',
  OFFLINE_FIXTURE = 'offline_fixture',
}

export enum ReportFormat {
  PDF = 'PDF',
  HTML = 'HTML',
  CSV = 'CSV',
  JSON = 'JSON',
}


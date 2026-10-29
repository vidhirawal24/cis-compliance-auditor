/**
 * BaselineGuard - Frozen Zod Schemas v1.0.0
 * Source: Playbook v1.0, PRD v1.0 & Tech Stack v3.0
 * Form validation and runtime contract checking schemas
 */

import { z } from 'zod';
import {
  EvaluationStatus,
  SeverityLevel,
  PlatformFamily,
  SimulationVerdict,
  ExecutionState,
  UserRole,
  CollectionMethod,
  ReportFormat,
} from './enums';

export const evaluationStatusSchema = z.nativeEnum(EvaluationStatus);
export const severityLevelSchema = z.nativeEnum(SeverityLevel);
export const platformFamilySchema = z.nativeEnum(PlatformFamily);
export const simulationVerdictSchema = z.nativeEnum(SimulationVerdict);
export const executionStateSchema = z.nativeEnum(ExecutionState);
export const userRoleSchema = z.nativeEnum(UserRole);
export const collectionMethodSchema = z.nativeEnum(CollectionMethod);
export const reportFormatSchema = z.nativeEnum(ReportFormat);

// -------------------------------------------------------------
// Evidence & Provenance Schemas
// -------------------------------------------------------------

export const evidenceRefSchema = z.object({
  sha256: z.string().length(64, 'SHA-256 must be a 64-character hex string'),
  source_command: z.string().min(1, 'Source command or API endpoint ID is required'),
  artifact_uri: z.string().min(1, 'Artifact URI is required'),
  timestamp: z.string().datetime({ message: 'Must be a valid ISO 8601 UTC timestamp' }),
});

export const normalizedEvidenceSchema = z.object({
  schema_version: z.literal('1.0.0'),
  org_id: z.string().uuid(),
  asset_id: z.string().uuid(),
  platform: platformFamilySchema,
  vendor: z.string().min(1),
  model: z.string().min(1),
  os_or_firmware_version: z.string().min(1),
  collector_version: z.string().min(1),
  collection_method: collectionMethodSchema,
  collected_at: z.string().datetime(),
  facts: z.record(z.unknown()),
  evidence_refs: z.array(evidenceRefSchema),
  supported_capabilities: z.array(z.string()),
  unsupported_capabilities: z.array(z.string()),
  errors: z.array(z.string()),
});

// -------------------------------------------------------------
// Authentication & Organization Form Schemas
// -------------------------------------------------------------

export const loginFormSchema = z.object({
  email: z.string().email('Valid corporate email address required'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
});

export const passwordResetFormSchema = z.object({
  email: z.string().email('Valid corporate email address required'),
});

export const mfaVerifyFormSchema = z.object({
  code: z.string().regex(/^\d{6}$/, 'Must be a 6-digit verification code'),
});

export const orgCreateFormSchema = z.object({
  name: z.string().min(3, 'Workspace name must be at least 3 characters').max(64),
  slug: z.string().min(3, 'Slug must be at least 3 characters').regex(/^[a-z0-9-]+$/, 'Slug must only contain lowercase letters, numbers, and hyphens'),
});

// -------------------------------------------------------------
// Asset & Discovery Form Schemas
// -------------------------------------------------------------

export const assetFormSchema = z.object({
  hostname: z.string().min(1, 'Hostname is required').max(255),
  primary_ip: z.string().ip({ version: 'v4', message: 'Valid IPv4 address required' }),
  platform: platformFamilySchema,
  vendor: z.string().min(1, 'Vendor is required'),
  model: z.string().min(1, 'Model is required'),
  os_or_firmware_version: z.string().min(1, 'OS or Firmware version is required'),
  site: z.string().min(1, 'Site identifier is required'),
  environment: z.enum(['production', 'staging', 'lab']),
  criticality: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
  tags: z.array(z.string()).default([]),
  credential_reference_id: z.string().min(1, 'Vault secret reference is required (zero plaintext)'),
});

export const discoveryFormSchema = z.object({
  cidr_ranges: z.array(z.string().regex(/^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))$/, 'Invalid CIDR format')),
  ports_to_probe: z.array(z.number().int().min(1).max(65535)).default([22, 443, 80, 445, 3389]),
  scope_consent_confirmed: z.literal(true, {
    errorMap: () => ({ message: 'You must confirm scope authorization prior to discovery' }),
  }),
});

// -------------------------------------------------------------
// Scan Launch & Schedule Schemas
// -------------------------------------------------------------

export const scanLaunchSchema = z.object({
  target_asset_ids: z.array(z.string().uuid()).min(1, 'At least one target asset must be selected'),
  policy_pack_id: z.string().uuid('Valid Policy Pack ID required'),
  profile_level: z.enum(['LEVEL_1', 'LEVEL_2']),
  read_only_confirmed: z.literal(true, {
    errorMap: () => ({ message: 'Audit scans are strictly read-only. Confirmation is required.' }),
  }),
});

export const scanScheduleFormSchema = z.object({
  name: z.string().min(3, 'Schedule name must be at least 3 characters'),
  cron_expression: z.string().min(5, 'Valid 5-field cron expression required'),
  target_asset_group: z.string().min(1, 'Target group or tag is required'),
  policy_pack_id: z.string().uuid(),
  profile_level: z.enum(['LEVEL_1', 'LEVEL_2']),
  is_active: z.boolean().default(true),
});

// -------------------------------------------------------------
// Policy Exception & Review Schemas
// -------------------------------------------------------------

export const exceptionRequestSchema = z.object({
  finding_id: z.string().uuid(),
  reason: z.string().min(10, 'Business and technical justification must be at least 10 characters'),
  approver_email: z.string().email('Valid approver email required'),
  expires_at: z.string().datetime({ message: 'Valid expiration date required' }),
});

export const manualReviewSubmissionSchema = z.object({
  verdict: z.enum(['PASS', 'FAIL']),
  justification: z.string().min(10, 'Attestation rationale is required'),
  evidence_file_ids: z.array(z.string().uuid()).min(1, 'At least one human evidence artifact must be attached'),
});

// -------------------------------------------------------------
// Service Safety Contract & Approval Schemas
// -------------------------------------------------------------

export const serviceSafetyContractFormSchema = z.object({
  name: z.string().min(3, 'Contract name required'),
  description: z.string().min(5, 'Description required'),
  source_cidr: z.string().regex(/^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))$/, 'Valid source CIDR required'),
  destination_cidr: z.string().regex(/^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))$/, 'Valid destination CIDR required'),
  port_range: z.string().regex(/^[0-9]+(-[0-9]+)?$/, 'Valid port or range (e.g. 22 or 80-443)'),
  protocol: z.enum(['TCP', 'UDP', 'ICMP', 'ANY']),
  mandatory: z.boolean().default(true),
});

export const approvalSubmissionSchema = z.object({
  plan_id: z.string().uuid(),
  plan_hash: z.string().length(64, 'Valid plan SHA-256 hash required'),
  justification: z.string().min(10, 'Approval justification required'),
  separation_of_duties_acknowledged: z.literal(true, {
    errorMap: () => ({ message: 'Approver cannot be the same persona as the plan operator.' }),
  }),
  backup_readiness_verified: z.literal(true, {
    errorMap: () => ({ message: 'Pre-change snapshot backup must be verified before sign-off.' }),
  }),
});


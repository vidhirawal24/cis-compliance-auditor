import React, { lazy, Suspense } from 'react';
import { ErrorBoundary } from '../components/common/ErrorBoundary';
import { Routes, Route, Navigate } from 'react-router-dom';
import { AppLayout } from '../components/layout/AppLayout';
import { AuthGuard } from '../auth/AuthGuard';
import { ScreenDataBoundary } from '../components/common/ScreenDataBoundary';
import { UserRole } from '../contracts/v1/enums';

// 19 Route Shells
const AuthShell = lazy(() => import('./shells/01_AuthShell').then(module => ({ default: module.AuthShell })));
const OrgSelectShell = lazy(() => import('./shells/02_OrgSelectShell').then(module => ({ default: module.OrgSelectShell })));
const OverviewShell = lazy(() => import('./shells/03_OverviewShell').then(module => ({ default: module.OverviewShell })));
const AssetInventoryShell = lazy(() => import('./shells/04_AssetInventoryShell').then(module => ({ default: module.AssetInventoryShell })));
const AssetDetailShell = lazy(() => import('./shells/05_AssetDetailShell').then(module => ({ default: module.AssetDetailShell })));
const ScanCenterShell = lazy(() => import('./shells/06_ScanCenterShell').then(module => ({ default: module.ScanCenterShell })));
const PolicyLibraryShell = lazy(() => import('./shells/07_PolicyLibraryShell').then(module => ({ default: module.PolicyLibraryShell })));
const ExceptionsShell = lazy(() => import('./shells/08_ExceptionsShell').then(module => ({ default: module.ExceptionsShell })));
const FindingsShell = lazy(() => import('./shells/09_FindingsShell').then(module => ({ default: module.FindingsShell })));
const SecurityGraphShell = lazy(() => import('./shells/10_SecurityGraphShell').then(module => ({ default: module.SecurityGraphShell })));
const RiskScenariosShell = lazy(() => import('./shells/11_RiskScenariosShell').then(module => ({ default: module.RiskScenariosShell })));
const RemediationPlannerShell = lazy(() => import('./shells/12_RemediationPlannerShell').then(module => ({ default: module.RemediationPlannerShell })));
const WhatIfSimulatorShell = lazy(() => import('./shells/13_WhatIfSimulatorShell').then(module => ({ default: module.WhatIfSimulatorShell })));
const ApprovalsHardeningShell = lazy(() => import('./shells/14_ApprovalsHardeningShell').then(module => ({ default: module.ApprovalsHardeningShell })));
const VerificationProofShell = lazy(() => import('./shells/15_VerificationProofShell').then(module => ({ default: module.VerificationProofShell })));
const ReportsHistoryShell = lazy(() => import('./shells/16_ReportsHistoryShell').then(module => ({ default: module.ReportsHistoryShell })));
const NotificationsTicketsShell = lazy(() => import('./shells/17_NotificationsTicketsShell').then(module => ({ default: module.NotificationsTicketsShell })));
const AdminSecurityShell = lazy(() => import('./shells/18_AdminSecurityShell').then(module => ({ default: module.AdminSecurityShell })));
const SystemStatesShell = lazy(() => import('./shells/19_SystemStatesShell').then(module => ({ default: module.SystemStatesShell })));

export const AppRouter: React.FC = () => {
  return (
    <ErrorBoundary><Suspense fallback={<p role="status">Loading screen...</p>}><Routes>
      {/* 01: Authentication Boundary (Public) */}
      <Route path="/auth/*" element={<AuthShell />} />
      <Route path="/auth/login" element={<AuthShell />} />

      {/* 02: Organization Selection / Tenant Switcher */}
      <Route
        path="/orgs"
        element={
          <AuthGuard>
            <ScreenDataBoundary familyOverride="02"><OrgSelectShell /></ScreenDataBoundary>
          </AuthGuard>
        }
      />

      {/* Main Tenant Application Shell Layout */}
      <Route
        path="/orgs/:orgId"
        element={
          <AuthGuard>
            <AppLayout />
          </AuthGuard>
        }
      >
        <Route index element={<Navigate to="overview" replace />} />

        {/* 03: Overview Dashboard (M34, M35, E07) */}
        <Route path="overview" element={<OverviewShell />} />

        {/* 04: Asset Inventory (E01, E02, E03) */}
        <Route path="assets" element={<AssetInventoryShell />} />
        <Route path="assets/discover" element={<AssetInventoryShell />} />
        <Route path="assets/import" element={<AssetInventoryShell />} />

        {/* 05: Asset Details (M12, M14, M15, E06) */}
        <Route path="assets/:assetId" element={<AssetDetailShell />} />
        <Route path="assets/:assetId/interfaces" element={<AssetDetailShell />} />
        <Route path="assets/:assetId/findings" element={<AssetDetailShell />} />
        <Route path="assets/:assetId/snapshots" element={<AssetDetailShell />} />

        {/* 06: Scan Center (M13, E04, E08, E18) */}
        <Route path="scans" element={<ScanCenterShell />} />
        <Route path="scans/new" element={<ScanCenterShell />} />
        <Route path="scans/:scanId" element={<ScanCenterShell />} />
        <Route path="scans/schedules" element={<ScanCenterShell />} />

        {/* 07: Policy Library (M17, M18, M19, E11, E20, I19) */}
        <Route path="policies" element={<PolicyLibraryShell />} />
        <Route path="policies/:policyId" element={<PolicyLibraryShell />} />
        <Route path="policies/upgrade-preview" element={<PolicyLibraryShell />} />

        {/* 08: Exceptions & Manual Reviews (E12, E14) */}
        <Route path="exceptions" element={<ExceptionsShell />} />
        <Route path="manual-reviews" element={<ExceptionsShell />} />

        {/* 09: Findings Explorer (M36, M37, E29) */}
        <Route path="findings" element={<FindingsShell />} />
        <Route path="findings/:findingId" element={<FindingsShell />} />

        {/* 10: Security Graph (I01, I03, I05) */}
        <Route path="graph" element={<SecurityGraphShell />} />

        {/* 11: Risk Scenarios (I02, I04, I05) */}
        <Route path="risk-scenarios" element={<RiskScenariosShell />} />
        <Route path="risk-scenarios/:scenarioId" element={<RiskScenariosShell />} />
        <Route path="scenarios" element={<RiskScenariosShell />} />
        <Route path="scenarios/:scenarioId" element={<RiskScenariosShell />} />

        {/* 12: Remediation Planner (I06, I07, I08, I10) */}
        <Route
          path="planner"
          element={
            <AuthGuard allowedRoles={[UserRole.OWNER, UserRole.ADMIN, UserRole.OPERATOR, UserRole.APPROVER]}>
              <RemediationPlannerShell />
            </AuthGuard>
          }
        />
        <Route
          path="planner/:planId"
          element={
            <AuthGuard allowedRoles={[UserRole.OWNER, UserRole.ADMIN, UserRole.OPERATOR, UserRole.APPROVER]}>
              <RemediationPlannerShell />
            </AuthGuard>
          }
        />

        {/* 13: What-If Simulator (I11, I12, I13, I14) */}
        <Route
          path="simulator"
          element={
            <AuthGuard allowedRoles={[UserRole.OWNER, UserRole.ADMIN, UserRole.OPERATOR, UserRole.APPROVER]}>
              <WhatIfSimulatorShell />
            </AuthGuard>
          }
        />
        <Route
          path="simulator/:simId"
          element={
            <AuthGuard allowedRoles={[UserRole.OWNER, UserRole.ADMIN, UserRole.OPERATOR, UserRole.APPROVER]}>
              <WhatIfSimulatorShell />
            </AuthGuard>
          }
        />

        {/* 14: Approvals & Hardening (E21, E23, I15) */}
        <Route
          path="approvals"
          element={
            <AuthGuard allowedRoles={[UserRole.OWNER, UserRole.ADMIN, UserRole.APPROVER, UserRole.OPERATOR]}>
              <ApprovalsHardeningShell />
            </AuthGuard>
          }
        />
        <Route
          path="changes"
          element={
            <AuthGuard allowedRoles={[UserRole.OWNER, UserRole.ADMIN, UserRole.OPERATOR, UserRole.APPROVER]}>
              <ApprovalsHardeningShell />
            </AuthGuard>
          }
        />
        <Route
          path="changes/:changeId"
          element={
            <AuthGuard allowedRoles={[UserRole.OWNER, UserRole.ADMIN, UserRole.OPERATOR, UserRole.APPROVER]}>
              <ApprovalsHardeningShell />
            </AuthGuard>
          }
        />

        {/* 15: Verification & Proof (I16, I17, I18) */}
        <Route
          path="verifications"
          element={
            <AuthGuard allowedRoles={[UserRole.OWNER, UserRole.ADMIN, UserRole.AUDITOR, UserRole.APPROVER]}>
              <VerificationProofShell />
            </AuthGuard>
          }
        />
        <Route
          path="proof-packages/:packageId"
          element={
            <AuthGuard allowedRoles={[UserRole.OWNER, UserRole.ADMIN, UserRole.AUDITOR, UserRole.APPROVER]}>
              <VerificationProofShell />
            </AuthGuard>
          }
        />

        {/* 16: Reports & Drift (M38, E05, E07, E28) */}
        <Route path="reports" element={<ReportsHistoryShell />} />
        <Route path="reports/drift" element={<ReportsHistoryShell />} />
        <Route path="reports/executive" element={<ReportsHistoryShell />} />

        {/* 17: Notifications & Tickets (E26, E27) */}
        <Route path="notifications" element={<NotificationsTicketsShell />} />
        <Route path="integrations" element={<NotificationsTicketsShell />} />

        {/* 18: Admin & Security Governance (E15, E16, E17, E19) */}
        <Route
          path="admin/*"
          element={
            <AuthGuard allowedRoles={[UserRole.OWNER, UserRole.ADMIN]}>
              <AdminSecurityShell />
            </AuthGuard>
          }
        />

        {/* 19: System States Showcase */}
        <Route path="system-states" element={<SystemStatesShell />} />
      </Route>

      {/* Root Fallback */}
      <Route path="/" element={<Navigate to="/orgs" replace />} />
      <Route path="*" element={<SystemStatesShell />} />
    </Routes></Suspense></ErrorBoundary>
  );
};


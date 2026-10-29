import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '../auth/context';
import { ApiProvider } from '../api/context';
import { AppRouter } from '../routes/AppRouter';
import { DEMO_ORG_ID } from '../fixtures/demoData';
import { fixtureStore } from '../api/store';

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false } },
});

const renderWithRoute = (initialPath: string) => {
  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ApiProvider>
          <MemoryRouter initialEntries={[initialPath]}>
            <AppRouter />
          </MemoryRouter>
        </ApiProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
};

describe('BaselineGuard - Phase 5 Suite: Security Graph & Cross-Layer Risk', () => {
  beforeEach(() => {
    fixtureStore.reset();
  });

  // -------------------------------------------------------------
  // Test 1: Graph rendering from typed nodes and edges (I01)
  // -------------------------------------------------------------
  it('01: renders security graph with typed nodes, evidence edges, and interactive canvas (I01)', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/graph`);

    // Verify header and subtitle
    expect(screen.getByText('Cross-Layer Security & Topology Graph (I01, I03)')).toBeInTheDocument();
    expect(
      screen.getByText(/Interactive Cytoscape\.js canvas showing evidence-backed topology/i)
    ).toBeInTheDocument();

    // Verify Cytoscape canvas container
    expect(screen.getByTestId('cytoscape-canvas')).toBeInTheDocument();

    // Verify node and edge counts badge
    expect(screen.getByText(/15 NODES • 13 EDGES/i)).toBeInTheDocument();

    // Verify legend displays all 5 typed node categories
    expect(screen.getByText('Asset')).toBeInTheDocument();
    expect(screen.getByText('Subnet')).toBeInTheDocument();
    expect(screen.getByText('Interface')).toBeInTheDocument();
    expect(screen.getByText('Service')).toBeInTheDocument();
    expect(screen.getByText('Finding (Violation)')).toBeInTheDocument();
  });

  // -------------------------------------------------------------
  // Test 2: Node selection and evidence drill-down (I01)
  // -------------------------------------------------------------
  it('02: supports node selection and evidence drill-down drawer (I01)', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/graph`);

    // Switch to Accessible Table View to select a specific node deterministically
    const switchBtn = screen.getByRole('button', { name: /Accessible Table View/i });
    fireEvent.click(switchBtn);

    // Locate node a10 (DEMO-ASR-WAN) in table and click "Locate in Graph"
    const a10Cells = screen.getAllByText('a10');
    expect(a10Cells.length).toBeGreaterThanOrEqual(1);

    const locateButtons = screen.getAllByRole('button', { name: /Locate in Graph/i });
    expect(locateButtons.length).toBeGreaterThanOrEqual(1);
    fireEvent.click(locateButtons[3]); // a10 is at index 3 in nodes list

    // Verify View switches to Graph and Evidence Drill-Down Drawer opens
    expect(screen.getByText('Node Evidence Drill-Down')).toBeInTheDocument();
    expect(screen.getByText('DEMO-ASR-WAN')).toBeInTheDocument();
    expect(screen.getByText('198.51.100.254')).toBeInTheDocument();
    expect(screen.getByText('Topology Adjacency')).toBeInTheDocument();

    // Verify drill-down action button to Findings Explorer
    expect(screen.getByRole('button', { name: /View Evidence in Findings Explorer/i })).toBeInTheDocument();
  });

  // -------------------------------------------------------------
  // Test 3: Severity, node type, and search filtering (I01)
  // -------------------------------------------------------------
  it('03: filters graph elements by node type, severity, and text query (I01)', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/graph`);

    // Switch to table mode for deterministic list inspection
    const switchBtn = screen.getByRole('button', { name: /Accessible Table View/i });
    fireEvent.click(switchBtn);

    // Filter by type "asset"
    const typeSelect = screen.getByLabelText(/Filter Node Type/i);
    fireEvent.change(typeSelect, { target: { value: 'asset' } });

    // Verify only asset nodes are present, non-asset nodes are filtered out
    expect(screen.getByText('DEMO-FG100F (Edge)')).toBeInTheDocument();
    expect(screen.getByText('DEMO-UBUNTU-APP')).toBeInTheDocument();
    expect(screen.queryByText('Untrusted Internet')).not.toBeInTheDocument();
    expect(screen.queryByText('M20: Telnet Active')).not.toBeInTheDocument();

    // Filter by severity "CRITICAL"
    fireEvent.change(typeSelect, { target: { value: 'ALL' } });
    const severitySelect = screen.getByLabelText(/Filter Severity/i);
    fireEvent.change(severitySelect, { target: { value: 'CRITICAL' } });

    // Verify only critical findings remain
    expect(screen.getByText('M20: Telnet Active')).toBeInTheDocument();
    expect(screen.getByText('M22: Permit Any Any')).toBeInTheDocument();
    expect(screen.queryByText('M30: VLAN 1 Mgmt')).not.toBeInTheDocument(); // High severity, filtered out
  });

  // -------------------------------------------------------------
  // Test 4: Missing topology and uncertainty messaging (I05)
  // -------------------------------------------------------------
  it('04: displays topology coverage percentage and model uncertainty notice (I05)', () => {
    const { unmount } = renderWithRoute(`/orgs/${DEMO_ORG_ID}/graph`);

    // Verify Topology Uncertainty banner on Security Graph view
    expect(screen.getByText(/Topology Coverage & Model Uncertainty Notice \(I05\)/i)).toBeInTheDocument();
    expect(screen.getByText('95% COVERAGE')).toBeInTheDocument();
    expect(
      screen.getByText(/Unassessed subnet segments \(e\.g\. 10\.200\.0\.0\/16\) are marked conditional/i)
    ).toBeInTheDocument();

    unmount();

    // Navigate to Risk Scenarios view and verify scenario boundary limitation
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/scenarios`);
    const boundaryNotices = screen.getAllByText(/Topology Boundary Limitation \(I05\):/i);
    expect(boundaryNotices.length).toBeGreaterThanOrEqual(1);
    expect(
      screen.getByText(/Unassessed legacy switch configs in rack 4B could introduce unobserved alternate paths/i)
    ).toBeInTheDocument();
  });

  // -------------------------------------------------------------
  // Test 5: Risk scenarios with source finding IDs and causal explanations (I02, I04)
  // -------------------------------------------------------------
  it('05: renders correlated risk scenarios with contributing findings and causal chain (I02, I04)', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/scenarios`);

    // Verify header
    expect(screen.getByText('Correlated Risk Scenarios & Lateral Movement (I02, I04, I05)')).toBeInTheDocument();

    // Verify Scenario 1
    expect(
      screen.getByText('Cross-Device Attack Chain: Inbound Perimeter Bypass to Internal App Host')
    ).toBeInTheDocument();
    expect(screen.getByText('Risk Score: 94 / 100')).toBeInTheDocument();
    expect(screen.getByText(/92% Explainability Confidence/i)).toBeInTheDocument();

    // Verify Contributing Source Finding IDs
    expect(screen.getByText('find-acl-permissive-02')).toBeInTheDocument();
    expect(screen.getByText('find-telnet-01')).toBeInTheDocument();
    expect(screen.getByText('find-vlan1-switch-04')).toBeInTheDocument();
    expect(screen.getByText('find-ssh-root-login-05')).toBeInTheDocument();

    // Verify Root-Cause Causal Sequence (I04)
    const causalHeaders = screen.getAllByText(/Root-Cause Causal Sequence \(I04\)/i);
    expect(causalHeaders.length).toBe(3);
    expect(screen.getByText('Inbound traffic permitted via ASA wildcard ACL')).toBeInTheDocument();
    expect(screen.getByText('Plaintext Telnet credentials sniffable across management subnet')).toBeInTheDocument();
    expect(screen.getByText('Direct root login enabled on Ubuntu application server')).toBeInTheDocument();

    // Verify Business Impact
    expect(
      screen.getByText(/High risk of complete core network takeover and lateral movement into PCI-DSS scoped databases/i)
    ).toBeInTheDocument();
  });

  // -------------------------------------------------------------
  // Test 6: Keyboard-accessible table fallback (I01)
  // -------------------------------------------------------------
  it('06: toggles accessible table fallback mode displaying nodes and evidence edges (I01)', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/graph`);

    // Click switch to Accessible Table View
    const switchBtn = screen.getByRole('button', { name: /Accessible Table View/i });
    fireEvent.click(switchBtn);

    // Verify Node Directory table headers and content
    expect(screen.getByText(/Topology Node Directory/i)).toBeInTheDocument();
    expect(screen.getByText('Node ID')).toBeInTheDocument();
    expect(screen.getByText('Network / Platform')).toBeInTheDocument();

    // Verify Evidence-Backed Relationship Edges table headers and content
    expect(screen.getByText(/Evidence-Backed Relationship Edges/i)).toBeInTheDocument();
    expect(screen.getByText('Edge ID')).toBeInTheDocument();
    expect(screen.getByText('Relation (I01)')).toBeInTheDocument();

    // Verify specific edges and confirmed confidence badges
    expect(screen.getByText('e1')).toBeInTheDocument();
    expect(screen.getByText('e2')).toBeInTheDocument();
    const confirmedBadges = screen.getAllByText('CONFIRMED');
    expect(confirmedBadges.length).toBeGreaterThanOrEqual(5);
  });

  // -------------------------------------------------------------
  // Test 7: Empty and filter mismatch states
  // -------------------------------------------------------------
  it('07: displays graceful empty states when search or filters yield zero results', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/graph`);

    // Search for nonexistent node
    const searchInput = screen.getByPlaceholderText(/Search graph/i);
    fireEvent.change(searchInput, { target: { value: 'nonexistent-hostname-xyz' } });

    // Verify empty state overlay on canvas
    expect(screen.getByText('No Graph Nodes Match Active Filters')).toBeInTheDocument();
    expect(
      screen.getByText(/Adjust the node type, severity filter, or search query to display topology elements/i)
    ).toBeInTheDocument();

    // Switch to table mode and verify table empty state
    const switchBtn = screen.getByRole('button', { name: /Accessible Table View/i });
    fireEvent.click(switchBtn);
    expect(screen.getByText('No graph nodes found matching filter criteria.')).toBeInTheDocument();
  });

  // -------------------------------------------------------------
  // Test 8: No unsupported path presented as verified (I03, I05)
  // -------------------------------------------------------------
  it('08: enforces invariant that unsupported reachability paths are NOT presented as verified (I03, I05)', () => {
    renderWithRoute(`/orgs/${DEMO_ORG_ID}/graph`);

    // Configure Path Explorer from internal App server (a03) to external Internet (ext-inet)
    // Directed graph has routes_to from ext-inet to a06 to a10 to a11 to a03, NOT reverse!
    const sourceSelect = screen.getByLabelText(/Path Source Node/i);
    fireEvent.change(sourceSelect, { target: { value: 'a03' } });

    const targetSelect = screen.getByLabelText(/Path Target Node/i);
    fireEvent.change(targetSelect, { target: { value: 'ext-inet' } });

    // Click "Trace Path (I03)"
    const traceBtn = screen.getByRole('button', { name: /Trace Path/i });
    fireEvent.click(traceBtn);

    // Verify system explicitly reports that NO verified path exists!
    expect(
      screen.getByText(/No verified traversal path exists between a03 and ext-inet under current firewall rules/i)
    ).toBeInTheDocument();

    // Confirm that "Verified Traversable Reachability Path Found" is NOT in document!
    expect(screen.queryByText(/Verified Traversable Reachability Path Found/i)).not.toBeInTheDocument();
  });
});

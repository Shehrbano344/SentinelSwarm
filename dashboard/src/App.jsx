// App.jsx - Updated with runtime API key configuration and approve/reject actions
import { useState, useEffect, useMemo } from 'react';
import './App.css';

const API_URL = 'http://localhost:8000/alerts/';

const severityColors = {
  Critical: '#ff2d78',
  High: '#ff8c42',
  Medium: '#39ff8f',
  Low: '#4fd1ff',
  Unknown: '#6b4d8f',
};

const severityOrder = { Critical: 4, High: 3, Medium: 2, Low: 1, Unknown: 0 };

function formatConfidence(conf) {
  if (conf === undefined || conf === null) return '—';
  return `${Math.round(conf * 100)}%`;
}

function SeverityBadge({ severity }) {
  const s = severity || 'Unknown';
  return (
    <span className="badge" style={{ backgroundColor: `${severityColors[s]}22`, color: severityColors[s], border: `1px solid ${severityColors[s]}55` }}>
      {s}
    </span>
  );
}

function TraceDetail({ trace }) {
  if (!trace) return <p className="empty-trace">No reasoning trace available for this alert.</p>;
  const { severity, confidence, explanation, evidence_used, threat_intel_matches, recommended_action } = trace;
  return (
    <div className="trace-content">
      <div className="trace-row">
        <span className="trace-label">Severity</span>
        <SeverityBadge severity={severity} />
      </div>
      <div className="trace-row">
        <span className="trace-label">Confidence</span>
        <div className="conf-wrap">
          <div className="conf-bar"><div style={{ width: formatConfidence(confidence) }} /></div>
          <span className="conf-pct">{formatConfidence(confidence)}</span>
        </div>
      </div>
      <div className="trace-block">
        <span className="trace-label">Explanation</span>
        <p>{explanation || 'No explanation available.'}</p>
      </div>
      <div className="trace-block">
        <span className="trace-label">Evidence Used</span>
        <p className="mono">{evidence_used?.length ? evidence_used.join(', ') : 'None recorded'}</p>
      </div>
      <div className="trace-block">
        <span className="trace-label">Threat Intel Matches</span>
        <p className="mono">{threat_intel_matches?.length ? threat_intel_matches.join(', ') : 'No matches'}</p>
      </div>
      <div className="trace-block">
        <span className="trace-label">Recommended Action</span>
        <p>{recommended_action || 'None specified'}</p>
      </div>
    </div>
  );
}

function ReasoningModal({ open, onClose, trace }) {
  if (!open) return null;
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <button className="close-btn" onClick={onClose}>✕</button>
        <h2>Reasoning Trace</h2>
        <TraceDetail trace={trace} />
      </div>
    </div>
  );
}

function DashboardPage({ alerts, backendUp, fetchAlerts }) {
  const [selected, setSelected] = useState(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');
  const [search, setSearch] = useState('');
  const [sortKey, setSortKey] = useState('timestamp');
  const [sortDir, setSortDir] = useState('desc');

  const openModal = (trace) => {
    setSelected(trace);
    setModalOpen(true);
  };

  const handleApprove = async (id) => {
    try {
      await fetch(`${API_URL}${id}/approve`, { method: 'POST' });
      fetchAlerts();
    } catch (e) { console.error(e); }
  };

  const handleReject = async (id) => {
    try {
      await fetch(`${API_URL}${id}/reject`, { method: 'POST' });
      fetchAlerts();
    } catch (e) { console.error(e); }
  };

  const stats = useMemo(() => {
    const total = alerts.length;
    const critical = alerts.filter((a) => a.reasoning_trace?.severity === 'Critical').length;
    const pending = alerts.filter((a) => (a.status || 'pending') === 'pending').length;
    const approved = alerts.filter((a) => a.status === 'approved').length;
    return { total, critical, pending, approved };
  }, [alerts]);

  const filtered = useMemo(() => {
    let result = [...alerts];
    if (severityFilter !== 'All') result = result.filter((a) => (a.reasoning_trace?.severity || 'Unknown') === severityFilter);
    if (statusFilter !== 'All') result = result.filter((a) => (a.status || 'pending') === statusFilter);
    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter((a) => a.source?.toLowerCase().includes(q) || a.raw_log?.toLowerCase().includes(q) || a.ip_address?.toLowerCase().includes(q) || a.domain?.toLowerCase().includes(q));
    }
    result.sort((a, b) => {
      let av, bv;
      if (sortKey === 'severity') { av = severityOrder[a.reasoning_trace?.severity || 'Unknown']; bv = severityOrder[b.reasoning_trace?.severity || 'Unknown']; }
      else if (sortKey === 'timestamp') { av = new Date(a.timestamp).getTime(); bv = new Date(b.timestamp).getTime(); }
      else { av = a[sortKey]; bv = b[sortKey]; }
      if (av < bv) return sortDir === 'asc' ? -1 : 1;
      if (av > bv) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
    return result;
  }, [alerts, severityFilter, statusFilter, search, sortKey, sortDir]);

  const toggleSort = (key) => {
    if (sortKey === key) setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
    else { setSortKey(key); setSortDir('desc'); }
  };

  return (
    <>
      <header className="topbar">
        <div>
          <h1>Alert Triage</h1>
          <span className="topbar-sub">AI-generated severity classifications, reviewed by you</span>
        </div>
        <button className="refresh-btn" onClick={fetchAlerts}>⟳ Refresh</button>
      </header>

      <div className="summary-cards">
        <div className="stat-card"><span className="stat-value">{stats.total}</span><span className="stat-label">Total Alerts</span></div>
        <div className="stat-card critical"><span className="stat-value">{stats.critical}</span><span className="stat-label">Critical</span></div>
        <div className="stat-card"><span className="stat-value">{stats.pending}</span><span className="stat-label">Pending Review</span></div>
        <div className="stat-card"><span className="stat-value">{stats.approved}</span><span className="stat-label">Approved</span></div>
      </div>

      <div className="toolbar">
        <input className="search-input" type="text" placeholder="Search source, log, IP, domain..." value={search} onChange={(e) => setSearch(e.target.value)} />
        <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
          <option value="All">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Unknown">Unknown</option>
        </select>
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          <option value="All">All Statuses</option>
          <option value="pending">Pending</option>
          <option value="approved">Approved</option>
          <option value="rejected">Rejected</option>
        </select>
      </div>

      <main className="main">
        {filtered.length === 0 ? (
          <div className="empty-state">No alerts match this filter.</div>
        ) : (
          <div className="table-wrap">
            <table className="alerts-table">
              <thead>
                <tr>
                  <th onClick={() => toggleSort('id')}>ID</th>
                  <th>Source</th>
                  <th onClick={() => toggleSort('timestamp')}>Timestamp {sortKey === 'timestamp' ? (sortDir === 'asc' ? '↑' : '↓') : ''}</th>
                  <th onClick={() => toggleSort('severity')}>Severity {sortKey === 'severity' ? (sortDir === 'asc' ? '↑' : '↓') : ''}</th>
                  <th>Status</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((alert) => (
                  <tr key={alert.id} className={alert.reasoning_trace?.severity === 'Critical' ? 'row-critical' : ''}>
                    <td className="mono">{alert.id}</td>
                    <td>{alert.source}</td>
                    <td className="mono">{new Date(alert.timestamp).toLocaleString()}</td>
                    <td><SeverityBadge severity={alert.reasoning_trace?.severity} /></td>
                    <td className="status-cell">{alert.status || 'pending'}</td>
                    <td>
                      <button className="view-btn" onClick={() => openModal(alert.reasoning_trace)}>View Trace</button>
                      <button className="approve-btn" onClick={() => handleApprove(alert.id)}>Approve</button>
                      <button className="reject-btn" onClick={() => handleReject(alert.id)}>Reject</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </main>

      <ReasoningModal open={modalOpen} onClose={() => setModalOpen(false)} trace={selected} />
    </>
  );
}

function InvestigationsPage({ alerts }) {
  const [activeId, setActiveId] = useState(alerts[0]?.id ?? null);
  const active = alerts.find((a) => a.id === activeId) || alerts[0];

  return (
    <>
      <header className="topbar">
        <div>
          <h1>Investigations</h1>
          <span className="topbar-sub">Step through each alert's full evidence and reasoning</span>
        </div>
      </header>
      <main className="main">
        <div className="investigate-layout">
          <div className="investigate-list">
            {alerts.map((a) => (
              <div key={a.id} className={`investigate-item ${active?.id === a.id ? 'active' : ''}`} onClick={() => setActiveId(a.id)}>
                <div className="investigate-item-top">
                  <span className="mono">#{a.id}</span>
                  <SeverityBadge severity={a.reasoning_trace?.severity} />
                </div>
                <div className="investigate-item-source">{a.source}</div>
                <div className="investigate-item-log">{a.raw_log}</div>
              </div>
            ))}
          </div>
          <div className="investigate-detail">
            {active ? (
              <>
                <div className="investigate-detail-header">
                  <h2>Alert #{active.id} — {active.source}</h2>
                  <span className="mono topbar-sub">{new Date(active.timestamp).toLocaleString()}</span>
                </div>
                <div className="investigate-raw">
                  <span className="trace-label">Raw Log</span>
                  <p className="mono">{active.raw_log}</p>
                  {active.ip_address && <p className="mono">IP: {active.ip_address}</p>}
                  {active.domain && <p className="mono">Domain: {active.domain}</p>}
                </div>
                <TraceDetail trace={active.reasoning_trace} />
              </>
            ) : (
              <div className="empty-state">No alerts to investigate yet.</div>
            )}
          </div>
        </div>
      </main>
    </>
  );
}

function ReportsPage({ alerts }) {
  const bySeverity = useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: 0 };
    alerts.forEach((a) => { counts[a.reasoning_trace?.severity || 'Unknown']++; });
    return counts;
  }, [alerts]);

  const bySource = useMemo(() => {
    const counts = {};
    alerts.forEach((a) => { counts[a.source] = (counts[a.source] || 0) + 1; });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [alerts]);

  const byStatus = useMemo(() => {
    const counts = { pending: 0, approved: 0, rejected: 0 };
    alerts.forEach((a) => { counts[a.status || 'pending']++; });
    return counts;
  }, [alerts]);

  const total = alerts.length || 1;

  return (
    <>
      <header className="topbar">
        <div>
          <h1>Reports</h1>
          <span className="topbar-sub">Aggregate view across all triaged alerts</span>
        </div>
      </header>
      <main className="main">
        <div className="report-grid">
          <div className="report-card">
            <h3>Severity breakdown</h3>
            {Object.entries(bySeverity).map(([sev, count]) => (
              <div className="report-bar-row" key={sev}>
                <span className="report-bar-label">{sev}</span>
                <div className="report-bar-track">
                  <div className="report-bar-fill" style={{ width: `${(count / total) * 100}%`, background: severityColors[sev] }} />
                </div>
                <span className="report-bar-count">{count}</span>
              </div>
            ))}
          </div>

          <div className="report-card">
            <h3>Review status</h3>
            {Object.entries(byStatus).map(([status, count]) => (
              <div className="report-bar-row" key={status}>
                <span className="report-bar-label" style={{ textTransform: 'capitalize' }}>{status}</span>
                <div className="report-bar-track">
                  <div className="report-bar-fill" style={{ width: `${(count / total) * 100}%`, background: '#a020f0' }} />
                </div>
                <span className="report-bar-count">{count}</span>
              </div>
            ))}
          </div>

          <div className="report-card wide">
            <h3>Alerts by source</h3>
            {bySource.map(([source, count]) => (
              <div className="report-bar-row" key={source}>
                <span className="report-bar-label">{source}</span>
                <div className="report-bar-track">
                  <div className="report-bar-fill" style={{ width: `${(count / total) * 100}%`, background: '#4fd1ff' }} />
                </div>
                <span className="report-bar-count">{count}</span>
              </div>
            ))}
          </div>
        </div>
      </main>
    </>
  );
}

function SettingsPage({ refreshInterval, setRefreshInterval, backendUp }) {
  const [apiKey, setApiKey] = useState('');
  const [msg, setMsg] = useState(null);

  const handleSave = async () => {
    try {
      const res = await fetch('http://localhost:8000/config/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: apiKey })
      });
      if (res.ok) {
        const data = await res.json();
        setMsg({ type: 'success', text: data.message || 'Key validated — live AI reasoning now active' });
      } else {
        const err = await res.json();
        setMsg({ type: 'error', text: err.detail || 'Invalid key — still using mocked reasoning' });
      }
    } catch (e) {
      setMsg({ type: 'error', text: 'Network error — still using mocked reasoning' });
    }
  };

  return (
    <>
      <header className="topbar">
        <div>
          <h1>Settings</h1>
          <span className="topbar-sub">System configuration and status</span>
        </div>
      </header>
      <main className="main">
        <div className="settings-card">
          <h3>Backend connection</h3>
          <div className="settings-row"><span>API endpoint</span><span className="mono">{API_URL}</span></div>
          <div className="settings-row"><span>Status</span><span className={`mono ${backendUp ? 'status-ok' : 'status-bad'}`}>{backendUp ? 'Connected' : 'Unreachable'}</span></div>
        </div>

        <div className="settings-card">
          <h3>Refresh interval</h3>
          <div className="settings-row">
            <span>Auto-refresh every</span>
            <select value={refreshInterval} onChange={(e) => setRefreshInterval(Number(e.target.value))}>
              <option value={10000}>10 seconds</option>
              <option value={15000}>15 seconds</option>
              <option value={30000}>30 seconds</option>
              <option value={60000}>60 seconds</option>
            </select>
          </div>
        </div>

        <div className="settings-card">
          <h3>AI reasoning</h3>
          <div className="settings-row">
            <span>Anthropic API key</span>
            <input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder="Enter API key" />
            <button className="save-btn" onClick={handleSave}>Save & Test</button>
          </div>
          {msg && (
            <div className={msg.type === 'success' ? 'msg-success' : 'msg-error'}>{msg.text}</div>
          )}
          <p className="settings-note">If a valid key is set, new alerts will be processed with live Claude reasoning. Existing alerts retain their stored traces.</p>
        </div>
      </main>
    </>
  );
}

function App() {
  const [alerts, setAlerts] = useState([]);
  const [backendUp, setBackendUp] = useState(true);
  const [page, setPage] = useState('dashboard');
  const [refreshInterval, setRefreshInterval] = useState(15000);

  const fetchAlerts = async () => {
    try {
      const res = await fetch(API_URL);
      const data = await res.json();
      setAlerts(data);
      setBackendUp(true);
    } catch (e) {
      console.error('Failed to fetch alerts', e);
      setBackendUp(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, refreshInterval);
    return () => clearInterval(interval);
  }, [refreshInterval]);

  const navItems = [
    { key: 'dashboard', label: 'Dashboard' },
    { key: 'investigations', label: 'Investigations' },
    { key: 'reports', label: 'Reports' },
    { key: 'settings', label: 'Settings' },
  ];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-mark">S</div>
          <div>
            <div className="brand-name">SentinelSwarm</div>
            <div className="brand-sub">SOC Triage</div>
          </div>
        </div>

        <nav className="sidebar-nav">
          {navItems.map((item) => (
            <div key={item.key} className={`nav-item ${page === item.key ? 'active' : ''}`} onClick={() => setPage(item.key)}>
              <span className="nav-dot" /> {item.label}
            </div>
          ))}
        </nav>

        <div className="sidebar-footer">
          <span className={`status-dot ${backendUp ? 'up' : 'down'}`} />
          <span className="status-label">{backendUp ? 'Backend Connected' : 'Backend Unreachable'}</span>
        </div>
      </aside>

      <div className="content">
        {page === 'dashboard' && <DashboardPage alerts={alerts} backendUp={backendUp} fetchAlerts={fetchAlerts} />}
        {page === 'investigations' && <InvestigationsPage alerts={alerts} />}
        {page === 'reports' && <ReportsPage alerts={alerts} />}
        {page === 'settings' && <SettingsPage refreshInterval={refreshInterval} setRefreshInterval={setRefreshInterval} backendUp={backendUp} />}
      </div>
    </div>
  );
}

export default App;

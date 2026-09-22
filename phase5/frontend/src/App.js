import React, { useState, useEffect } from 'react';
import AllowlistDenylist from './components/AllowlistDenylist';
import Analytics from './components/Analytics';
import Blocklists from './components/Blocklists';

// Hash-based routing: no react-router dependency.
//   #/             -> dashboard (overview)
//   #/lists         -> Allowlist / Denylist
//   #/blocklists     -> Blocklists
//   #/analytics     -> Analytics
function App() {
  const [stats, setStats] = useState(null);
  const [queries, setQueries] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [view, setView] = useState('dashboard');

  const fetchData = async () => {
    try {
      const [statsRes, queriesRes, anomaliesRes] = await Promise.all([
        fetch('/api/stats'),
        fetch('/api/queries?limit=20'),
        fetch('/api/anomalies?limit=20'),
      ]);

      if (!statsRes.ok || !queriesRes.ok || !anomaliesRes.ok) {
        throw new Error('Failed to fetch data');
      }

      const [statsData, queriesData, anomaliesData] = await Promise.all([
        statsRes.json(),
        queriesRes.json(),
        anomaliesRes.json(),
      ]);

      setStats(statsData);
      setQueries(queriesData);
      setAnomalies(anomaliesData);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const onHash = () => {
      const h = window.location.hash.replace('#/', '').split('/')[0] || 'dashboard';
      setView(h || 'dashboard');
    };
    onHash();
    window.addEventListener('hashchange', onHash);
    fetchData();
    const interval = setInterval(fetchData, 10000); // Poll every 10 seconds
    return () => {
      window.removeEventListener('hashchange', onHash);
      clearInterval(interval);
    };
  }, []);

  const navigate = (v) => {
    window.location.hash = '#/' + v;
  };

  const formatTimestamp = (ts) => {
    try {
      return new Date(ts).toLocaleString();
    } catch {
      return ts;
    }
  };

  const getScoreBadge = (score) => {
    if (score >= 0.5) return <span className="badge badge-score-high">{score.toFixed(2)}</span>;
    if (score >= 0.3) return <span className="badge badge-score-medium">{score.toFixed(2)}</span>;
    return <span className="badge badge-score-low">{score.toFixed(2)}</span>;
  };

  if (loading) {
    return (
      <div className="container">
        <div className="loading">Loading dashboard…</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="container">
        <div className="error">Error: {error}</div>
      </div>
    );
  }

  return (
    <div className="container">
      <nav className="nav">
        <span className="nav-title">HannibaalDNS</span>
        <button className={view === 'dashboard' ? 'nav-active' : ''} onClick={() => navigate('dashboard')}>
          Overview
        </button>
        <button className={view === 'lists' ? 'nav-active' : ''} onClick={() => navigate('lists')}>
          Allowlist / Denylist
        </button>
        <button className={view === 'blocklists' ? 'nav-active' : ''} onClick={() => navigate('blocklists')}>
          Blocklists
        </button>
        <button className={view === 'analytics' ? 'nav-active' : ''} onClick={() => navigate('analytics')}>
          Analytics
        </button>
      </nav>

      {view === 'dashboard' && (
        <div>
          <div className="header">
            <h1>Dashboard</h1>
          </div>

          <div className="stats-grid">
            <div className="stat-card">
              <h3>Total Queries (last hour)</h3>
              <div className="value">{stats?.total_queries || 0}</div>
            </div>
            <div className="stat-card blocked">
              <h3>Blocked Queries</h3>
              <div className="value">{stats?.blocked_queries || 0}</div>
            </div>
            <div className="stat-card time">
              <h3>Avg Response Time</h3>
              <div className="value">{(stats?.avg_response_time || 0).toFixed(4)}s</div>
            </div>
          </div>

          <div className="table-section">
            <h2>Recent Queries</h2>
            {queries.length === 0 ? (
              <p style={{ color: '#666' }}>No queries recorded</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Client IP</th>
                    <th>Domain</th>
                    <th>Type</th>
                    <th>Blocked</th>
                    <th>Response Time (s)</th>
                  </tr>
                </thead>
                <tbody>
                  {queries.map((q, i) => (
                    <tr key={i}>
                      <td>{formatTimestamp(q.timestamp)}</td>
                      <td>{q.client_ip}</td>
                      <td>{q.domain}</td>
                      <td>{q.query_type}</td>
                      <td className={q.blocked ? 'blocked-yes' : 'blocked-no'}>
                        {q.blocked ? 'Yes' : 'No'}
                      </td>
                      <td>{q.response_time?.toFixed(4) || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          <div className="table-section">
            <h2>Recent Anomalies</h2>
            {anomalies.length === 0 ? (
              <p style={{ color: '#666' }}>No anomalies detected</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Domain</th>
                    <th>Client IP</th>
                    <th>Score</th>
                    <th>Reasons</th>
                  </tr>
                </thead>
                <tbody>
                  {anomalies.map((a, i) => (
                    <tr key={i}>
                      <td>{formatTimestamp(a.timestamp)}</td>
                      <td>{a.domain}</td>
                      <td>{a.client_ip}</td>
                      <td>{getScoreBadge(a.score)}</td>
                      <td>{a.reasons || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {view === 'lists' && <AllowlistDenylist />}
      {view === 'blocklists' && <Blocklists />}
      {view === 'analytics' && <Analytics />}
    </div>
  );
}

export default App;
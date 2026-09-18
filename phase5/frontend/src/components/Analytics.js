import React, { useState, useEffect } from 'react';

/**
 * Analytics-style breakdown (NextDNS Analytics tab).
 * Uses only query_log / anomaly_log data that already exists — no GeoIP,
 * no DNSSEC%, no encrypted-DNS% since none of that is tracked in the schema.
 */
export default function Analytics() {
  const [summary, setSummary] = useState(null);
  const [resolved, setResolved] = useState([]);
  const [blocked, setBlocked] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [sumRes, resRes, blkRes] = await Promise.all([
        fetch('/api/analytics/summary'),
        fetch('/api/analytics/top-domains?blocked=false&limit=20'),
        fetch('/api/analytics/top-domains?blocked=true&limit=20'),
      ]);
      if (!sumRes.ok || !resRes.ok || !blkRes.ok) throw new Error('Failed to fetch analytics');
      const [s, r, b] = await Promise.all([
        sumRes.json(), resRes.json(), blkRes.json(),
      ]);
      setSummary(s);
      setResolved(r);
      setBlocked(b);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="page">
        <div className="loading">Loading analytics…</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="page">
        <div className="error">Error: {error}</div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1>Analytics</h1>
        <p className="page-subtitle">
          Domain breakdown over the last {summary?.window_hours || 24} hours.
          Based on query_log only.
        </p>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <h3>Total Queries</h3>
          <div className="value">{summary?.total_queries ?? 0}</div>
        </div>
        <div className="stat-card blocked">
          <h3>Blocked Queries</h3>
          <div className="value">{summary?.blocked_queries ?? 0}</div>
        </div>
        <div className="stat-card">
          <h3>Resolved Queries</h3>
          <div className="value">{summary?.resolved_queries ?? 0}</div>
        </div>
        <div className="stat-card time">
          <h3>% Blocked</h3>
          <div className="value">{summary?.percent_blocked ?? 0}%</div>
        </div>
      </div>

      <div className="analytics-columns">
        <div className="table-section">
          <h2>Resolved Domains</h2>
          {resolved.length === 0 ? (
            <p style={{ color: '#666' }}>No resolved domains yet</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Domain</th>
                  <th style={{ textAlign: 'right' }}>Queries</th>
                </tr>
              </thead>
              <tbody>
                {resolved.map((row) => (
                  <tr key={row.domain}>
                    <td>{row.domain}</td>
                    <td style={{ textAlign: 'right' }}>{row.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="table-section">
          <h2>Blocked Domains</h2>
          {blocked.length === 0 ? (
            <p style={{ color: '#666' }}>No blocked domains yet</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Domain</th>
                  <th style={{ textAlign: 'right' }}>Queries</th>
                </tr>
              </thead>
              <tbody>
                {blocked.map((row) => (
                  <tr key={row.domain}>
                    <td>{row.domain}</td>
                    <td style={{ textAlign: 'right' }}>{row.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
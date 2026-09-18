import React, { useState, useEffect } from 'react';

/**
 * Per-client Allowlist / Denylist management (NextDNS-style).
 * No global list — every domain is scoped to the client_ip in the URL.
 */
export default function AllowlistDenylist() {
  const [clientIp, setClientIp] = useState('127.0.0.1');
  const [lists, setLists] = useState({ custom_allowlist: [], custom_blocklist: [], profile_name: 'default' });
  const [addDomain, setAddDomain] = useState('');
  const [activeList, setActiveList] = useState('allowlist'); // 'allowlist' | 'denylist'
  const [message, setMessage] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchLists = async (ip) => {
    setLoading(true);
    try {
      const res = await fetch(`/api/clients/${encodeURIComponent(ip)}/lists`);
      const data = await res.json();
      setLists(data);
    } catch (err) {
      setMessage({ type: 'error', text: `Failed to load lists: ${err.message}` });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLists(clientIp);
  }, [clientIp]);

  const handleAdd = async (e) => {
    e.preventDefault();
    const domain = addDomain.trim();
    if (!domain) return;
    setMessage(null);
    try {
      const res = await fetch(`/api/clients/${encodeURIComponent(clientIp)}/lists`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'add', list: activeList, domain }),
      });
      const data = await res.json();
      if (!res.ok) {
        setMessage({ type: 'error', text: data.error || 'Failed to add domain' });
        return;
      }
      setLists((prev) => ({
        ...prev,
        [`custom_${activeList}`]: data[`custom_${activeList}`],
      }));
      setAddDomain('');
      setMessage({ type: 'success', text: `${domain} added to ${activeList}` });
    } catch (err) {
      setMessage({ type: 'error', text: `Request failed: ${err.message}` });
    }
  };

  const handleRemove = async (domain) => {
    setMessage(null);
    try {
      const res = await fetch(`/api/clients/${encodeURIComponent(clientIp)}/lists`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'remove', list: activeList, domain }),
      });
      const data = await res.json();
      if (!res.ok) {
        setMessage({ type: 'error', text: data.error || 'Failed to remove domain' });
        return;
      }
      setLists((prev) => ({
        ...prev,
        [`custom_${activeList}`]: data[`custom_${activeList}`],
      }));
      setMessage({ type: 'success', text: `${domain} removed from ${activeList}` });
    } catch (err) {
      setMessage({ type: 'error', text: `Request failed: ${err.message}` });
    }
  };

  const domains = activeList === 'allowlist' ? lists.custom_allowlist : lists.custom_blocklist;

  return (
    <div className="page">
      <div className="page-header">
        <h1>Allowlist / Denylist</h1>
        <p className="page-subtitle">
          Per-client domain rules. Domains added here are scoped to{' '}
          <strong>{clientIp}</strong> only — no global list.
        </p>
      </div>

      <div className="client-selector">
        <label>
          Client IP:
          <input
            type="text"
            value={clientIp}
            onChange={(e) => setClientIp(e.target.value)}
            placeholder="192.168.1.50"
            style={{ marginLeft: '8px', padding: '6px 10px', width: '220px' }}
          />
        </label>
        <span className="profile-badge">Profile: {lists.profile_name}</span>
      </div>

      <div className="tabs">
        <button
          className={`tab ${activeList === 'allowlist' ? 'tab-active' : ''}`}
          onClick={() => { setActiveList('allowlist'); setMessage(null); }}
        >
          Allowlist
        </button>
        <button
          className={`tab ${activeList === 'denylist' ? 'tab-active' : ''}`}
          onClick={() => { setActiveList('denylist'); setMessage(null); }}
        >
          Denylist
        </button>
      </div>

      <div className="list-widget">
        <form className="add-form" onSubmit={handleAdd}>
          <input
            type="text"
            value={addDomain}
            onChange={(e) => setAddDomain(e.target.value)}
            placeholder="Add a domain..."
            className="add-input"
          />
          <button type="submit" className="btn btn-primary" disabled={loading}>
            Add
          </button>
        </form>

        <div className="domain-list">
          {loading ? (
            <p className="muted">Loading…</p>
          ) : domains.length === 0 ? (
            <p className="muted">No domains yet</p>
          ) : (
            <ul className="domain-items">
              {domains.map((d) => (
                <li key={d} className="domain-item">
                  <span className="domain-name">{d}</span>
                  <button
                    className="btn btn-danger btn-sm"
                    onClick={() => handleRemove(d)}
                  >
                    Remove
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        {message && (
          <div className={`toast ${message.type === 'error' ? 'toast-error' : 'toast-success'}`}>
            {message.text}
          </div>
        )}
      </div>
    </div>
  );
}
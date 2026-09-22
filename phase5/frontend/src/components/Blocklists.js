import React, { useState, useEffect, useCallback } from 'react';

// Mirrors config.BLOCKLIST_PRESETS on the backend. These are UI shortcuts
// only -- the registry accepts any http(s) URL, preset or not (see the
// "Add custom list" form below). Kept in sync manually; if a preset is
// added/removed in config.py, update this list too.
const PRESETS = [
  { key: 'stevenblack', name: 'StevenBlack hosts', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', format: 'hosts' },
  { key: 'oisd_small', name: 'OISD small', url: 'https://small.oisd.nl', format: 'adblock' },
  { key: 'oisd_big', name: 'OISD big', url: 'https://big.oisd.nl', format: 'adblock' },
  { key: 'hagezi_light', name: 'HaGeZi Multi LIGHT', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/dnsmasq/light.txt', format: 'dnsmasq' },
  { key: 'hagezi_multi', name: 'HaGeZi Multi NORMAL', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/dnsmasq/multi.txt', format: 'dnsmasq' },
  { key: 'adguard_base', name: 'AdGuard DNS filter (base)', url: 'https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/general_url.txt', format: 'adblock' },
];

const FORMATS = ['hosts', 'domains', 'adblock', 'dnsmasq', 'wildcard'];

function formatTimestamp(ts) {
  if (!ts) return 'never';
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

export default function Blocklists() {
  const [lists, setLists] = useState([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState(null);
  const [busyIds, setBusyIds] = useState(new Set());
  const [refreshingAll, setRefreshingAll] = useState(false);

  // Custom-add form state
  const [customName, setCustomName] = useState('');
  const [customUrl, setCustomUrl] = useState('');
  const [customFormat, setCustomFormat] = useState('hosts');
  const [addingCustom, setAddingCustom] = useState(false);
  const [addingPreset, setAddingPreset] = useState(null); // preset key currently being added

  const fetchLists = useCallback(async () => {
    try {
      const res = await fetch('/api/blocklists');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setLists(data);
    } catch (err) {
      setMessage({ type: 'error', text: `Failed to load blocklists: ${err.message}` });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLists();
    const interval = setInterval(fetchLists, 15000);
    return () => clearInterval(interval);
  }, [fetchLists]);

  const withBusy = async (id, fn) => {
    setBusyIds((prev) => new Set(prev).add(id));
    try {
      await fn();
    } finally {
      setBusyIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  };

  const registeredUrls = new Set(lists.map((l) => l.url));

  const addList = async ({ name, url, format }) => {
    setMessage(null);
    try {
      const res = await fetch('/api/blocklists', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, url, format, enabled: true }),
      });
      const data = await res.json();
      if (!res.ok) {
        setMessage({ type: 'error', text: data.error || `Failed to add ${name}` });
        return false;
      }
      setLists((prev) => [...prev, data]);
      setMessage({ type: 'success', text: `${name} added` });
      return true;
    } catch (err) {
      setMessage({ type: 'error', text: `Request failed: ${err.message}` });
      return false;
    }
  };

  const handleAddPreset = async (preset) => {
    setAddingPreset(preset.key);
    await addList({ name: preset.name, url: preset.url, format: preset.format });
    setAddingPreset(null);
  };

  const handleAddCustom = async (e) => {
    e.preventDefault();
    const name = customName.trim();
    const url = customUrl.trim();
    if (!name || !url) {
      setMessage({ type: 'error', text: 'Name and URL are required' });
      return;
    }
    setAddingCustom(true);
    const ok = await addList({ name, url, format: customFormat });
    setAddingCustom(false);
    if (ok) {
      setCustomName('');
      setCustomUrl('');
      setCustomFormat('hosts');
    }
  };

  const handleToggle = (list) => withBusy(list.id, async () => {
    setMessage(null);
    try {
      const res = await fetch(`/api/blocklists/${list.id}/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !list.enabled }),
      });
      const data = await res.json();
      if (!res.ok) {
        setMessage({ type: 'error', text: data.error || 'Failed to toggle list' });
        return;
      }
      setLists((prev) => prev.map((l) => (l.id === list.id ? data : l)));
    } catch (err) {
      setMessage({ type: 'error', text: `Request failed: ${err.message}` });
    }
  });

  const handleRefresh = (list) => withBusy(list.id, async () => {
    setMessage(null);
    try {
      const res = await fetch(`/api/blocklists/${list.id}/refresh`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) {
        setMessage({ type: 'error', text: data.error || 'Failed to refresh list' });
        return;
      }
      if (data.status !== 'ok') {
        setMessage({ type: 'error', text: `${list.name}: refresh failed, keeping last good copy` });
      } else {
        setMessage({ type: 'success', text: `${list.name} refreshed (${data.entry_count} entries)` });
      }
      setLists((prev) => prev.map((l) => (l.id === list.id ? { ...l, ...data } : l)));
    } catch (err) {
      setMessage({ type: 'error', text: `Request failed: ${err.message}` });
    }
  });

  const handleRemove = (list) => withBusy(list.id, async () => {
    if (!window.confirm(`Remove "${list.name}"? This cannot be undone.`)) return;
    setMessage(null);
    try {
      const res = await fetch(`/api/blocklists/${list.id}`, { method: 'DELETE' });
      const data = await res.json();
      if (!res.ok) {
        setMessage({ type: 'error', text: data.error || 'Failed to remove list' });
        return;
      }
      setLists((prev) => prev.filter((l) => l.id !== list.id));
      setMessage({ type: 'success', text: `${list.name} removed` });
    } catch (err) {
      setMessage({ type: 'error', text: `Request failed: ${err.message}` });
    }
  });

  const handleRefreshAll = async () => {
    setRefreshingAll(true);
    setMessage(null);
    try {
      const res = await fetch('/api/blocklists/refresh', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) {
        setMessage({ type: 'error', text: data.error || 'Refresh all failed' });
        return;
      }
      setLists(data.lists);
      setMessage({
        type: data.status === 'ok' ? 'success' : 'error',
        text: data.status === 'ok' ? 'All lists refreshed' : 'Refresh completed with failures — check individual lists',
      });
    } catch (err) {
      setMessage({ type: 'error', text: `Request failed: ${err.message}` });
    } finally {
      setRefreshingAll(false);
    }
  };

  const totalEntries = lists.reduce((sum, l) => sum + (l.enabled ? l.entry_count || 0 : 0), 0);

  return (
    <div className="page">
      <div className="page-header">
        <h1>Blocklists</h1>
        <p className="page-subtitle">
          Global blocklist registry — every list here applies to all clients, on top of
          any per-client allow/deny rules. {lists.length} list{lists.length === 1 ? '' : 's'} registered,{' '}
          {totalEntries.toLocaleString()} active entries.
        </p>
      </div>

      <div className="list-widget">
        <div className="blocklists-toolbar">
          <button
            className="btn btn-primary"
            onClick={handleRefreshAll}
            disabled={refreshingAll || lists.length === 0}
          >
            {refreshingAll ? 'Refreshing…' : 'Refresh all'}
          </button>
        </div>

        {loading ? (
          <p className="muted">Loading…</p>
        ) : lists.length === 0 ? (
          <p className="muted">No blocklists registered yet — add one below.</p>
        ) : (
          <table className="blocklists-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Format</th>
                <th>Entries</th>
                <th>Last updated</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {lists.map((list) => {
                const busy = busyIds.has(list.id);
                return (
                  <tr key={list.id} className={list.enabled ? '' : 'row-disabled'}>
                    <td>
                      <div className="domain-name">{list.name}</div>
                      <div className="muted list-url">{list.url}</div>
                    </td>
                    <td>{list.format}</td>
                    <td>{(list.entry_count || 0).toLocaleString()}</td>
                    <td>{formatTimestamp(list.last_updated)}</td>
                    <td>
                      <span className={`badge ${list.enabled ? 'badge-score-low' : 'badge-score-medium'}`}>
                        {list.enabled ? 'enabled' : 'disabled'}
                      </span>
                    </td>
                    <td className="blocklists-actions">
                      <button
                        className="btn btn-sm"
                        onClick={() => handleToggle(list)}
                        disabled={busy}
                      >
                        {list.enabled ? 'Disable' : 'Enable'}
                      </button>
                      <button
                        className="btn btn-sm"
                        onClick={() => handleRefresh(list)}
                        disabled={busy}
                      >
                        Refresh
                      </button>
                      <button
                        className="btn btn-danger btn-sm"
                        onClick={() => handleRemove(list)}
                        disabled={busy}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        {message && (
          <div className={`toast ${message.type === 'error' ? 'toast-error' : 'toast-success'}`}>
            {message.text}
          </div>
        )}
      </div>

      <div className="list-widget">
        <h2 className="blocklists-subheading">Add a preset</h2>
        <div className="preset-grid">
          {PRESETS.map((preset) => {
            const registered = registeredUrls.has(preset.url);
            return (
              <div key={preset.key} className="preset-card">
                <div className="domain-name">{preset.name}</div>
                <div className="muted">{preset.format}</div>
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => handleAddPreset(preset)}
                  disabled={registered || addingPreset === preset.key}
                >
                  {registered ? 'Added' : addingPreset === preset.key ? 'Adding…' : 'Add'}
                </button>
              </div>
            );
          })}
        </div>
      </div>

      <div className="list-widget">
        <h2 className="blocklists-subheading">Add a custom list</h2>
        <form className="custom-list-form" onSubmit={handleAddCustom}>
          <input
            type="text"
            value={customName}
            onChange={(e) => setCustomName(e.target.value)}
            placeholder="Name"
            className="add-input"
          />
          <input
            type="text"
            value={customUrl}
            onChange={(e) => setCustomUrl(e.target.value)}
            placeholder="https://example.com/list.txt"
            className="add-input custom-list-url"
          />
          <select
            value={customFormat}
            onChange={(e) => setCustomFormat(e.target.value)}
            className="custom-list-format"
          >
            {FORMATS.map((f) => (
              <option key={f} value={f}>{f}</option>
            ))}
          </select>
          <button type="submit" className="btn btn-primary" disabled={addingCustom}>
            {addingCustom ? 'Adding…' : 'Add'}
          </button>
        </form>
      </div>
    </div>
  );
}

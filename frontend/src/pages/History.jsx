import React, { useEffect, useState } from 'react';
import { Search, Download, Trash2, ExternalLink, ShieldCheck, AlertTriangle } from 'lucide-react';
import { getHistory, deleteHistoryRecord, getReportDownloadUrl } from '../services/api';

export default function History({ onSelectJob }) {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [modeFilter, setModeFilter] = useState('');
  const [classFilter, setClassFilter] = useState('');

  const fetchRecords = () => {
    setLoading(true);
    getHistory(search, modeFilter, classFilter)
      .then(res => setItems(res.items || []))
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    const timer = setTimeout(fetchRecords, 300);
    return () => clearTimeout(timer);
  }, [search, modeFilter, classFilter]);

  const handleDelete = async (jobId, filename) => {
    if (!window.confirm(`Delete analysis record for ${filename}?`)) return;
    try {
      await deleteHistoryRecord(jobId);
      setItems(prev => prev.filter(item => item.id !== jobId));
    } catch (err) {
      alert('Failed to delete record: ' + err.message);
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '28px' }}>
        <div>
          <h1 style={{ fontSize: '28px', fontWeight: '800', color: '#FFFFFF', marginBottom: '6px' }}>
            Analysis History
          </h1>
          <p style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>
            Search, filter, inspect past predictions, and download formal threat reports.
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="glass-card" style={{ padding: '16px 20px', marginBottom: '24px', display: 'flex', gap: '16px', alignItems: 'center' }}>
        <div style={{ flex: 1, position: 'relative' }}>
          <Search size={18} color="var(--text-secondary)" style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)' }} />
          <input
            type="text"
            placeholder="Search by APK name, SHA-256 hash, or malware family..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              width: '100%',
              background: '#0D111A',
              border: '1px solid var(--card-border)',
              borderRadius: '12px',
              padding: '10px 14px 10px 42px',
              color: '#FFFFFF',
              fontSize: '14px',
              outline: 'none'
            }}
          />
        </div>

        <select
          value={modeFilter}
          onChange={(e) => setModeFilter(e.target.value)}
          style={{
            background: '#0D111A',
            border: '1px solid var(--card-border)',
            borderRadius: '12px',
            padding: '10px 14px',
            color: '#FFFFFF',
            fontSize: '14px',
            outline: 'none'
          }}
        >
          <option value="">All Modes</option>
          <option value="passive">Passive</option>
          <option value="active">Active</option>
        </select>

        <select
          value={classFilter}
          onChange={(e) => setClassFilter(e.target.value)}
          style={{
            background: '#0D111A',
            border: '1px solid var(--card-border)',
            borderRadius: '12px',
            padding: '10px 14px',
            color: '#FFFFFF',
            fontSize: '14px',
            outline: 'none'
          }}
        >
          <option value="">All Classifications</option>
          <option value="Benign">Benign Only</option>
          <option value="Malicious">Malicious Only</option>
          <option value="PHISHING / SUSPICIOUS REDIRECT">Phishing / Redirect</option>
          <option value="DATA LEAKAGE / PRIVACY RISK">Data Leakage / Privacy</option>
          <option value="Unknown">Unknown / Inconclusive</option>
        </select>
      </div>

      {/* History Table */}
      <div className="glass-card" style={{ padding: '0', overflow: 'hidden' }}>
        {loading ? (
          <div style={{ padding: '60px 0', textAlign: 'center', color: 'var(--text-secondary)' }}>
            Loading records...
          </div>
        ) : items.length === 0 ? (
          <div style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--text-secondary)' }}>
            No matching analysis records found.
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '14px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--card-border)', background: 'rgba(255, 255, 255, 0.02)' }}>
                <th style={{ padding: '16px 20px', color: 'var(--text-secondary)', fontWeight: '600' }}>Status</th>
                <th style={{ padding: '16px 20px', color: 'var(--text-secondary)', fontWeight: '600' }}>APK Name</th>
                <th style={{ padding: '16px 20px', color: 'var(--text-secondary)', fontWeight: '600' }}>Mode</th>
                <th style={{ padding: '16px 20px', color: 'var(--text-secondary)', fontWeight: '600' }}>Family</th>
                <th style={{ padding: '16px 20px', color: 'var(--text-secondary)', fontWeight: '600' }}>Confidence</th>
                <th style={{ padding: '16px 20px', color: 'var(--text-secondary)', fontWeight: '600' }}>Date</th>
                <th style={{ padding: '16px 20px', color: 'var(--text-secondary)', fontWeight: '600', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => {
                const cUpper = (item.classification || '').toUpperCase();
                const isMal = cUpper.includes('MALICIOUS');
                const isPhish = cUpper.includes('PHISHING') || cUpper.includes('REDIRECT');
                const isPrivacy = cUpper.includes('DATA LEAKAGE') || cUpper.includes('PRIVACY');
                const isUnk = cUpper.includes('UNKNOWN') || cUpper.includes('INCONCLUSIVE');

                let badgeColor = '#34D399';
                let badgeBg = 'rgba(16, 185, 129, 0.12)';
                let BadgeIcon = ShieldCheck;

                if (isMal) {
                  badgeColor = '#F87171';
                  badgeBg = 'rgba(239, 68, 68, 0.12)';
                  BadgeIcon = AlertTriangle;
                } else if (isPhish) {
                  badgeColor = '#FBBF24';
                  badgeBg = 'rgba(245, 158, 11, 0.12)';
                  BadgeIcon = AlertTriangle;
                } else if (isPrivacy) {
                  badgeColor = '#C084FC';
                  badgeBg = 'rgba(139, 92, 246, 0.12)';
                  BadgeIcon = AlertTriangle;
                } else if (isUnk) {
                  badgeColor = '#94A3B8';
                  badgeBg = 'rgba(100, 116, 139, 0.12)';
                  BadgeIcon = AlertTriangle;
                }

                return (
                  <tr key={item.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                    <td style={{ padding: '16px 20px' }}>
                      <span style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        padding: '4px 10px',
                        borderRadius: '20px',
                        fontSize: '12px',
                        fontWeight: '600',
                        background: badgeBg,
                        color: badgeColor
                      }}>
                        <BadgeIcon size={13} />
                        <span>{item.classification}</span>
                      </span>
                    </td>
                    <td style={{ padding: '16px 20px', fontWeight: '600', color: '#FFFFFF' }}>
                      {item.filename}
                    </td>
                    <td style={{ padding: '16px 20px', color: 'var(--text-secondary)', textTransform: 'capitalize' }}>
                      {item.analysis_mode}
                    </td>
                    <td style={{ padding: '16px 20px', color: isMal ? '#F87171' : 'var(--text-secondary)' }}>
                      {item.malware_family || 'None'}
                    </td>
                    <td style={{ padding: '16px 20px', fontWeight: '600' }}>
                      {item.confidence_score ? `${item.confidence_score}%` : 'N/A'}
                    </td>
                    <td style={{ padding: '16px 20px', color: 'var(--text-muted)', fontSize: '13px' }}>
                      {item.created_at ? new Date(item.created_at).toLocaleDateString() : 'N/A'}
                    </td>
                    <td style={{ padding: '16px 20px', textAlign: 'right' }}>
                      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                        <button
                          onClick={() => onSelectJob(item.id)}
                          className="btn-secondary"
                          style={{ padding: '6px 12px', fontSize: '12px' }}
                          title="View Result"
                        >
                          <ExternalLink size={14} />
                          <span>View</span>
                        </button>
                        <a
                          href={getReportDownloadUrl(item.id, 'pdf')}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="btn-secondary"
                          style={{ padding: '6px 12px', fontSize: '12px', textDecoration: 'none' }}
                          title="Download PDF Report"
                        >
                          <Download size={14} />
                        </a>
                        <button
                          onClick={() => handleDelete(item.id, item.filename)}
                          style={{ background: 'transparent', border: 'none', color: '#EF4444', cursor: 'pointer', padding: '6px' }}
                          title="Delete Record"
                        >
                          <Trash2 size={16} />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

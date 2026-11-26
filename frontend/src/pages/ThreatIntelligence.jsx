import React, { useEffect, useState } from 'react';
import { Cpu, Server, CheckCircle2, AlertCircle, Send, RefreshCw, Code2 } from 'lucide-react';
import { getTaxiiConfig, saveTaxiiConfig, testTaxiiConnection, shareTaxiiIntelligence, getHistory, getStixBundle } from '../services/api';

export default function ThreatIntelligence() {
  const [taxii, setTaxii] = useState({
    server_url: 'https://cti-taxii.oasis-open.org/taxii2/',
    collection_id: 'default-malware-feed',
    username: '',
    password: '',
    use_https: true,
    status: 'DISCONNECTED',
    status_message: 'Unconfigured'
  });

  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [saveMessage, setSaveMessage] = useState(null);

  // Sharing state
  const [recentRecords, setRecentRecords] = useState([]);
  const [selectedJobId, setSelectedJobId] = useState('');
  const [sharing, setSharing] = useState(false);
  const [shareResult, setShareResult] = useState(null);
  const [stixPreview, setStixPreview] = useState(null);

  useEffect(() => {
    getTaxiiConfig().then(data => {
      if (data.configured) setTaxii(data);
    }).catch(() => {});

    getHistory('', '', 'Malicious').then(res => {
      const items = res.items || [];
      setRecentRecords(items);
      if (items.length > 0) {
        setSelectedJobId(items[0].id);
        fetchStixPreview(items[0].id);
      }
    }).catch(() => {});
  }, []);

  const fetchStixPreview = (id) => {
    getStixBundle(id).then(bundle => setStixPreview(bundle)).catch(() => setStixPreview(null));
  };

  const handleSaveConfig = async (e) => {
    e.preventDefault();
    setSaveMessage(null);
    try {
      await saveTaxiiConfig(taxii);
      setSaveMessage({ type: 'success', text: 'TAXII server configuration saved successfully.' });
    } catch (err) {
      setSaveMessage({ type: 'error', text: err.message });
    }
  };

  const handleTestConnection = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await testTaxiiConnection();
      setTestResult({ type: 'success', message: res.message });
      setTaxii(prev => ({ ...prev, status: 'CONNECTED', status_message: res.message }));
    } catch (err) {
      setTestResult({ type: 'error', message: err.message });
      setTaxii(prev => ({ ...prev, status: 'ERROR', status_message: err.message }));
    } finally {
      setTesting(false);
    }
  };

  const handleShare = async () => {
    if (!selectedJobId) return;
    setSharing(true);
    setShareResult(null);
    try {
      const res = await shareTaxiiIntelligence(selectedJobId);
      setShareResult({ type: 'success', message: res.message });
    } catch (err) {
      setShareResult({ type: 'error', message: err.message });
    } finally {
      setSharing(false);
    }
  };

  return (
    <div>
      <div style={{ marginBottom: '28px' }}>
        <h1 style={{ fontSize: '28px', fontWeight: '800', color: '#FFFFFF', marginBottom: '6px' }}>
          STIX / TAXII Threat Intelligence
        </h1>
        <p style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>
          Generate standardized OASIS STIX 2.1 cyber observable bundles and publish indicators to TAXII 2.1 servers.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px', marginBottom: '24px' }}>
        {/* TAXII Server Configuration Card */}
        <div className="glass-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
            <Server size={20} color="var(--accent-blue)" />
            <h3 style={{ fontSize: '18px', fontWeight: '700', color: '#FFFFFF' }}>TAXII 2.1 Server Setup</h3>
          </div>

          {saveMessage && (
            <div style={{ 
              background: saveMessage.type === 'success' ? 'var(--status-benign-bg)' : 'var(--status-malicious-bg)',
              border: `1px solid ${saveMessage.type === 'success' ? 'var(--status-benign-border)' : 'var(--status-malicious-border)'}`,
              borderRadius: '10px',
              padding: '10px 14px',
              color: saveMessage.type === 'success' ? '#34D399' : '#F87171',
              fontSize: '13px',
              marginBottom: '16px'
            }}>
              {saveMessage.text}
            </div>
          )}

          <form onSubmit={handleSaveConfig} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '6px' }}>Server Root URL</label>
              <input
                type="text"
                value={taxii.server_url}
                onChange={(e) => setTaxii({ ...taxii, server_url: e.target.value })}
                required
                style={{ width: '100%', background: '#0D111A', border: '1px solid var(--card-border)', borderRadius: '10px', padding: '10px 14px', color: '#FFF', fontSize: '14px' }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '6px' }}>Collection ID</label>
              <input
                type="text"
                value={taxii.collection_id || ''}
                onChange={(e) => setTaxii({ ...taxii, collection_id: e.target.value })}
                placeholder="e.g., android-malware-feed"
                style={{ width: '100%', background: '#0D111A', border: '1px solid var(--card-border)', borderRadius: '10px', padding: '10px 14px', color: '#FFF', fontSize: '14px' }}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '6px' }}>Username (Optional)</label>
                <input
                  type="text"
                  value={taxii.username || ''}
                  onChange={(e) => setTaxii({ ...taxii, username: e.target.value })}
                  style={{ width: '100%', background: '#0D111A', border: '1px solid var(--card-border)', borderRadius: '10px', padding: '10px 14px', color: '#FFF', fontSize: '14px' }}
                />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '6px' }}>Password (Optional)</label>
                <input
                  type="password"
                  value={taxii.password || ''}
                  onChange={(e) => setTaxii({ ...taxii, password: e.target.value })}
                  style={{ width: '100%', background: '#0D111A', border: '1px solid var(--card-border)', borderRadius: '10px', padding: '10px 14px', color: '#FFF', fontSize: '14px' }}
                />
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '12px' }}>
              <button type="button" className="btn-secondary" onClick={handleTestConnection} disabled={testing}>
                <RefreshCw size={15} className={testing ? 'animate-spin' : ''} />
                <span>{testing ? 'Testing...' : 'Test Connection'}</span>
              </button>
              <button type="submit" className="btn-primary">
                Save Configuration
              </button>
            </div>
          </form>

          {testResult && (
            <div style={{ marginTop: '16px', padding: '12px', borderRadius: '10px', fontSize: '13px', background: testResult.type === 'success' ? 'var(--status-benign-bg)' : 'var(--status-malicious-bg)', color: testResult.type === 'success' ? '#34D399' : '#F87171' }}>
              {testResult.message}
            </div>
          )}
        </div>

        {/* Intelligence Dispatch Card */}
        <div className="glass-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
            <Send size={20} color="var(--accent-purple)" />
            <h3 style={{ fontSize: '18px', fontWeight: '700', color: '#FFFFFF' }}>Share STIX Threat Bundle</h3>
          </div>

          <div style={{ marginBottom: '18px' }}>
            <label style={{ display: 'block', fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '6px' }}>
              Select Malicious Sample to Publish
            </label>
            <select
              value={selectedJobId}
              onChange={(e) => {
                setSelectedJobId(e.target.value);
                fetchStixPreview(e.target.value);
              }}
              style={{ width: '100%', background: '#0D111A', border: '1px solid var(--card-border)', borderRadius: '10px', padding: '10px 14px', color: '#FFF', fontSize: '14px' }}
            >
              {recentRecords.length === 0 ? (
                <option value="">No completed malware records available</option>
              ) : (
                recentRecords.map(r => (
                  <option key={r.id} value={r.id}>
                    {r.filename} — {r.malware_family} ({r.confidence_score}%)
                  </option>
                ))
              )}
            </select>
          </div>

          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '1.5', marginBottom: '20px' }}>
            Generates compliant OASIS STIX 2.1 Indicator, Malware, and Relationship bundles connecting file hashes, family taxonomy, and confidence attributions.
          </p>

          <button
            className="btn-primary"
            onClick={handleShare}
            disabled={!selectedJobId || sharing}
            style={{ width: '100%', justifyContent: 'center' }}
          >
            <Send size={16} />
            <span>{sharing ? 'Transmitting STIX Bundle...' : 'Share Intelligence to TAXII Collection'}</span>
          </button>

          {shareResult && (
            <div style={{ marginTop: '16px', padding: '12px', borderRadius: '10px', fontSize: '13px', background: shareResult.type === 'success' ? 'var(--status-benign-bg)' : 'var(--status-malicious-bg)', color: shareResult.type === 'success' ? '#34D399' : '#F87171' }}>
              {shareResult.message}
            </div>
          )}
        </div>
      </div>

      {/* Live STIX 2.1 JSON Schema Preview */}
      <div className="glass-card">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
          <Code2 size={18} color="var(--accent-blue)" />
          <h3 style={{ fontSize: '16px', fontWeight: '700', color: '#FFFFFF' }}>STIX 2.1 Cyber Observable Preview</h3>
        </div>
        <pre style={{ 
          background: '#0D111A', 
          border: '1px solid var(--card-border)', 
          borderRadius: '12px', 
          padding: '16px', 
          color: '#38BDF8', 
          fontSize: '12px', 
          maxHeight: '260px', 
          overflowY: 'auto',
          fontFamily: 'monospace'
        }}>
          {stixPreview ? JSON.stringify(stixPreview, null, 2) : '// Select a malware analysis sample above to preview generated STIX 2.1 objects.'}
        </pre>
      </div>
    </div>
  );
}

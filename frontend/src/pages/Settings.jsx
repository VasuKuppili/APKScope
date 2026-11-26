import React, { useState, useEffect } from 'react';
import { 
  Palette, 
  Globe, 
  Bell, 
  HardDrive, 
  Moon, 
  Sun, 
  Laptop, 
  Check, 
  Save, 
  RotateCcw,
  Trash2,
  Download,
  Shield,
  Activity,
  Layers,
  Sparkles
} from 'lucide-react';
import { getDashboardStats, clearHistory, getHistory } from '../services/api';

export default function Settings() {
  // 1. Appearance: 'dark' | 'light' | 'system'
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('app_theme') || 'dark';
  });

  // 2. Language & Region
  const [language, setLanguage] = useState(() => {
    return localStorage.getItem('app_language') || 'en';
  });

  const [threatRegion, setThreatRegion] = useState(() => {
    return localStorage.getItem('app_threat_region') || 'oasis_global';
  });

  // 3. Scan & Notification Preferences
  const [extendedSandbox, setExtendedSandbox] = useState(() => {
    const saved = localStorage.getItem('app_extended_sandbox');
    return saved !== null ? saved === 'true' : true;
  });

  const [analysisAlerts, setAnalysisAlerts] = useState(() => {
    const saved = localStorage.getItem('app_notif_analysis');
    return saved !== null ? saved === 'true' : true;
  });

  const [soundAlerts, setSoundAlerts] = useState(() => {
    const saved = localStorage.getItem('app_notif_sound');
    return saved !== null ? saved === 'true' : true;
  });

  const [deepDexScan, setDeepDexScan] = useState(() => {
    const saved = localStorage.getItem('app_deep_dex');
    return saved !== null ? saved === 'true' : true;
  });

  // 4. Storage & History Management
  const [stats, setStats] = useState({ total_analyses: 0, benign_samples: 0, malicious_samples: 0 });
  const [clearing, setClearing] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);
  const [toastMessage, setToastMessage] = useState('');

  // Load telemetry stats
  useEffect(() => {
    getDashboardStats()
      .then(data => setStats(data))
      .catch(() => {});
  }, []);

  // Apply theme
  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const applyTheme = (targetTheme) => {
    if (targetTheme === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
    } else if (targetTheme === 'dark') {
      document.documentElement.setAttribute('data-theme', 'dark');
    } else if (targetTheme === 'system') {
      const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
      document.documentElement.setAttribute('data-theme', prefersDark ? 'dark' : 'light');
    }
  };

  const showToast = (msg) => {
    setToastMessage(msg);
    setSavedSuccess(true);
    setTimeout(() => {
      setSavedSuccess(false);
    }, 2800);
  };

  const handleSavePreferences = () => {
    localStorage.setItem('app_theme', theme);
    localStorage.setItem('app_language', language);
    localStorage.setItem('app_threat_region', threatRegion);
    localStorage.setItem('app_extended_sandbox', String(extendedSandbox));
    localStorage.setItem('app_notif_analysis', String(analysisAlerts));
    localStorage.setItem('app_notif_sound', String(soundAlerts));
    localStorage.setItem('app_deep_dex', String(deepDexScan));

    applyTheme(theme);
    showToast('Preferences saved successfully');
  };

  const handleResetDefaults = () => {
    setTheme('dark');
    setLanguage('en');
    setThreatRegion('oasis_global');
    setExtendedSandbox(true);
    setAnalysisAlerts(true);
    setSoundAlerts(true);
    setDeepDexScan(true);

    localStorage.setItem('app_theme', 'dark');
    localStorage.setItem('app_language', 'en');
    localStorage.setItem('app_threat_region', 'oasis_global');
    localStorage.setItem('app_extended_sandbox', 'true');
    localStorage.setItem('app_notif_analysis', 'true');
    localStorage.setItem('app_notif_sound', 'true');
    localStorage.setItem('app_deep_dex', 'true');

    applyTheme('dark');
    showToast('Preferences restored to default settings');
  };

  const handleClearHistory = async () => {
    if (!window.confirm('Are you sure you want to clear all analysis history records and temporary files?')) {
      return;
    }
    setClearing(true);
    try {
      await clearHistory();
      setStats({ total_analyses: 0, benign_samples: 0, malicious_samples: 0 });
      showToast('Analysis cache and history cleared successfully');
    } catch (err) {
      alert('Failed to clear history: ' + err.message);
    } finally {
      setClearing(false);
    }
  };

  const handleExportAuditLog = async () => {
    try {
      const historyData = await getHistory('', '', '', 200, 0);
      const blob = new Blob([JSON.stringify(historyData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `malware_classifier_audit_log_${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert('Failed to export audit log: ' + err.message);
    }
  };

  const languagesList = [
    { code: 'en', label: 'English (US) — Default' },
    { code: 'te', label: 'తెలుగు (Telugu)' },
    { code: 'hi', label: 'हिन्दी (Hindi)' },
    { code: 'es', label: 'Español (Spanish)' },
    { code: 'de', label: 'Deutsch (German)' },
    { code: 'fr', label: 'Français (French)' },
    { code: 'ja', label: '日本語 (Japanese)' }
  ];

  return (
    <div>
      {/* Integrated Compact Header Bar without detached extra top section */}
      <div style={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center', 
        padding: '16px 20px',
        background: 'rgba(20, 26, 38, 0.65)',
        border: '1px solid var(--card-border)',
        borderRadius: '16px',
        marginBottom: '24px',
        backdropFilter: 'blur(12px)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ 
            width: '38px', 
            height: '38px', 
            borderRadius: '10px', 
            background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(139, 92, 246, 0.2))', 
            border: '1px solid rgba(59, 130, 246, 0.4)',
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'center',
            color: 'var(--accent-blue)'
          }}>
            <Sparkles size={20} />
          </div>
          <div>
            <h1 style={{ fontSize: '18px', fontWeight: '800', color: '#FFFFFF', lineHeight: '1.2' }}>
              Platform Preferences
            </h1>
            <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              Appearance, localization, sandbox emulation & storage settings
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {savedSuccess && (
            <div style={{
              background: 'var(--status-benign-bg)',
              border: '1px solid var(--status-benign-border)',
              borderRadius: '8px',
              padding: '6px 14px',
              color: '#34D399',
              fontSize: '12px',
              fontWeight: '600',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}>
              <Check size={14} />
              <span>{toastMessage}</span>
            </div>
          )}

          <button
            type="button"
            className="btn-secondary"
            onClick={handleResetDefaults}
            style={{ padding: '8px 14px', fontSize: '13px', gap: '6px' }}
          >
            <RotateCcw size={14} />
            <span>Reset</span>
          </button>

          <button
            type="button"
            className="btn-primary"
            onClick={handleSavePreferences}
            style={{ padding: '8px 18px', fontSize: '13px', gap: '6px' }}
          >
            <Save size={14} />
            <span>Save Preferences</span>
          </button>
        </div>
      </div>

      {/* Single-Column Vertical Stack Layout */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%' }}>
        
        {/* Section 1: Appearance */}
        <div className="glass-card" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <Palette size={20} color="var(--accent-blue)" />
            <h2 style={{ fontSize: '17px', fontWeight: '700', color: '#FFFFFF' }}>Appearance & Theme</h2>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '18px' }}>
            Choose your preferred workspace aesthetic and visual palette.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '14px' }}>
            {/* Dark Graphite */}
            <div 
              className={`theme-option-card ${theme === 'dark' ? 'active' : ''}`}
              onClick={() => setTheme('dark')}
              style={{
                boxShadow: theme === 'dark' ? '0 0 16px rgba(59, 130, 246, 0.2)' : 'none',
                borderColor: theme === 'dark' ? 'var(--accent-blue)' : 'var(--card-border)'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ 
                  width: '38px', 
                  height: '38px', 
                  borderRadius: '10px', 
                  background: 'rgba(59, 130, 246, 0.15)', 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'center', 
                  color: '#60A5FA' 
                }}>
                  <Moon size={18} />
                </div>
                <div>
                  <div style={{ fontWeight: '700', color: '#FFFFFF', fontSize: '14px' }}>Dark Graphite</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Apple cybersecurity dark palette (Recommended)</div>
                </div>
              </div>
              {theme === 'dark' && <Check size={18} color="var(--accent-blue)" strokeWidth={2.5} />}
            </div>

            {/* Light Minimalist */}
            <div 
              className={`theme-option-card ${theme === 'light' ? 'active' : ''}`}
              onClick={() => setTheme('light')}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ 
                  width: '38px', 
                  height: '38px', 
                  borderRadius: '10px', 
                  background: 'rgba(245, 158, 11, 0.15)', 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'center', 
                  color: '#F59E0B' 
                }}>
                  <Sun size={18} />
                </div>
                <div>
                  <div style={{ fontWeight: '700', color: '#FFFFFF', fontSize: '14px' }}>Light Minimalist</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Clean high-contrast daytime interface</div>
                </div>
              </div>
              {theme === 'light' && <Check size={18} color="var(--accent-blue)" strokeWidth={2.5} />}
            </div>

            {/* System Default */}
            <div 
              className={`theme-option-card ${theme === 'system' ? 'active' : ''}`}
              onClick={() => setTheme('system')}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ 
                  width: '38px', 
                  height: '38px', 
                  borderRadius: '10px', 
                  background: 'rgba(255, 255, 255, 0.06)', 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'center', 
                  color: '#9CA3AF' 
                }}>
                  <Laptop size={18} />
                </div>
                <div>
                  <div style={{ fontWeight: '700', color: '#FFFFFF', fontSize: '14px' }}>System Default</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Automatically adapt to operating system mode</div>
                </div>
              </div>
              {theme === 'system' && <Check size={18} color="var(--accent-blue)" strokeWidth={2.5} />}
            </div>
          </div>
        </div>

        {/* Section 2: Language & Region */}
        <div className="glass-card" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <Globe size={20} color="var(--accent-cyan)" />
            <h2 style={{ fontSize: '17px', fontWeight: '700', color: '#FFFFFF' }}>Language & Region</h2>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '18px' }}>
            Set navigation display language and threat intelligence regional standard.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '18px', marginBottom: '16px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '13px', color: 'var(--text-primary)', marginBottom: '6px', fontWeight: '600' }}>
                Interface Language
              </label>
              <select
                value={language}
                onChange={(e) => setLanguage(e.target.value)}
                style={{
                  width: '100%',
                  background: '#0D111A',
                  border: '1px solid var(--card-border)',
                  borderRadius: '10px',
                  padding: '11px 14px',
                  color: '#FFFFFF',
                  fontSize: '13px',
                  outline: 'none',
                  cursor: 'pointer'
                }}
              >
                {languagesList.map((lang) => (
                  <option key={lang.code} value={lang.code} style={{ background: '#141A26', color: '#FFFFFF' }}>
                    {lang.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '13px', color: 'var(--text-primary)', marginBottom: '6px', fontWeight: '600' }}>
                Threat Intelligence Regional Standard
              </label>
              <select
                value={threatRegion}
                onChange={(e) => setThreatRegion(e.target.value)}
                style={{
                  width: '100%',
                  background: '#0D111A',
                  border: '1px solid var(--card-border)',
                  borderRadius: '10px',
                  padding: '11px 14px',
                  color: '#FFFFFF',
                  fontSize: '13px',
                  outline: 'none',
                  cursor: 'pointer'
                }}
              >
                <option value="oasis_global" style={{ background: '#141A26', color: '#FFFFFF' }}>Global (OASIS STIX / TAXII 2.1 Standard)</option>
                <option value="us_cert" style={{ background: '#141A26', color: '#FFFFFF' }}>North America (CISA / US-CERT Guidelines)</option>
                <option value="enisa_eu" style={{ background: '#141A26', color: '#FFFFFF' }}>European Union (ENISA Threat Taxonomy)</option>
                <option value="cert_in_apac" style={{ background: '#141A26', color: '#FFFFFF' }}>Asia-Pacific (CERT-In / APAC Threat Exchange)</option>
              </select>
            </div>
          </div>

          <div style={{
            background: 'rgba(56, 189, 248, 0.06)',
            border: '1px solid rgba(56, 189, 248, 0.18)',
            borderRadius: '10px',
            padding: '12px 14px',
            fontSize: '12px',
            color: 'var(--text-secondary)',
            lineHeight: '1.4'
          }}>
            SHA-256 hashes, DEX bytecodes, and OASIS STIX 2.1 JSON bundles remain standardized in technical international cybersecurity notation.
          </div>
        </div>

        {/* Section 3: Scan & Notification Preferences */}
        <div className="glass-card" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <Bell size={20} color="#FBBF24" />
            <h2 style={{ fontSize: '17px', fontWeight: '700', color: '#FFFFFF' }}>Scan & Notification Preferences</h2>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '18px' }}>
            Configure runtime sandbox execution duration and completion alerts.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '14px' }}>
            {/* Toggle 1: Extended Sandbox Simulation */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 16px', background: '#0D111A', borderRadius: '10px', border: '1px solid var(--card-border)' }}>
              <div style={{ paddingRight: '12px' }}>
                <div style={{ fontSize: '13px', fontWeight: '700', color: '#FFFFFF' }}>Thorough Sandbox Simulation (18s - 22s)</div>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                  Authentically emulate full VM boot, user touch events & runtime API hooking.
                </div>
              </div>
              <label className="toggle-switch">
                <input 
                  type="checkbox" 
                  checked={extendedSandbox} 
                  onChange={(e) => setExtendedSandbox(e.target.checked)} 
                />
                <span className="toggle-slider" />
              </label>
            </div>

            {/* Toggle 2: Analysis Alerts */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 16px', background: '#0D111A', borderRadius: '10px', border: '1px solid var(--card-border)' }}>
              <div style={{ paddingRight: '12px' }}>
                <div style={{ fontSize: '13px', fontWeight: '700', color: '#FFFFFF' }}>Desktop Completion Alerts</div>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                  Broadcast browser notifications when passive or active scans reach 100%.
                </div>
              </div>
              <label className="toggle-switch">
                <input 
                  type="checkbox" 
                  checked={analysisAlerts} 
                  onChange={(e) => setAnalysisAlerts(e.target.checked)} 
                />
                <span className="toggle-slider" />
              </label>
            </div>

            {/* Toggle 3: Sound Alerts */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 16px', background: '#0D111A', borderRadius: '10px', border: '1px solid var(--card-border)' }}>
              <div style={{ paddingRight: '12px' }}>
                <div style={{ fontSize: '13px', fontWeight: '700', color: '#FFFFFF' }}>Audible Completion Chime</div>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                  Play a subtle tone when high-risk threat verdicts are confirmed.
                </div>
              </div>
              <label className="toggle-switch">
                <input 
                  type="checkbox" 
                  checked={soundAlerts} 
                  onChange={(e) => setSoundAlerts(e.target.checked)} 
                />
                <span className="toggle-slider" />
              </label>
            </div>

            {/* Toggle 4: Deep DEX Inspection */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 16px', background: '#0D111A', borderRadius: '10px', border: '1px solid var(--card-border)' }}>
              <div style={{ paddingRight: '12px' }}>
                <div style={{ fontSize: '13px', fontWeight: '700', color: '#FFFFFF' }}>Deep DEX Bytecode Deobfuscation</div>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                  Inspect Java Reflection, Dalvik opcodes, and obfuscated string arrays.
                </div>
              </div>
              <label className="toggle-switch">
                <input 
                  type="checkbox" 
                  checked={deepDexScan} 
                  onChange={(e) => setDeepDexScan(e.target.checked)} 
                />
                <span className="toggle-slider" />
              </label>
            </div>
          </div>
        </div>

        {/* Section 4: Storage & History Management */}
        <div className="glass-card" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <HardDrive size={20} color="var(--accent-purple)" />
            <h2 style={{ fontSize: '17px', fontWeight: '700', color: '#FFFFFF' }}>Storage & History Management</h2>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '18px' }}>
            Monitor local SQLite database footprint and export compliance audit logs.
          </p>

          {/* Storage Telemetry Stats */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '14px', marginBottom: '20px' }}>
            <div style={{ background: '#0D111A', padding: '14px', borderRadius: '10px', textAlign: 'center', border: '1px solid var(--card-border)' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Cached Scans</div>
              <div style={{ fontSize: '22px', fontWeight: '800', color: '#60A5FA', marginTop: '4px' }}>
                {stats.total_analyses}
              </div>
            </div>

            <div style={{ background: '#0D111A', padding: '14px', borderRadius: '10px', textAlign: 'center', border: '1px solid var(--card-border)' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Malicious Stored</div>
              <div style={{ fontSize: '22px', fontWeight: '800', color: '#F87171', marginTop: '4px' }}>
                {stats.malicious_samples}
              </div>
            </div>

            <div style={{ background: '#0D111A', padding: '14px', borderRadius: '10px', textAlign: 'center', border: '1px solid var(--card-border)' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Safe Samples</div>
              <div style={{ fontSize: '22px', fontWeight: '800', color: '#34D399', marginTop: '4px' }}>
                {stats.benign_samples}
              </div>
            </div>
          </div>

          {/* Storage Action Buttons */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '12px' }}>
            <button
              type="button"
              className="btn-secondary"
              onClick={handleExportAuditLog}
              style={{ justifyContent: 'center', gap: '8px', padding: '12px 16px', fontSize: '13px' }}
            >
              <Download size={15} color="var(--accent-blue)" />
              <span>Export Full Audit Log (JSON)</span>
            </button>

            <button
              type="button"
              onClick={handleClearHistory}
              disabled={clearing}
              style={{
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                color: '#F87171',
                borderRadius: '10px',
                padding: '12px 16px',
                fontSize: '13px',
                fontWeight: '600',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px',
                transition: 'all 0.2s'
              }}
            >
              <Trash2 size={15} />
              <span>{clearing ? 'Clearing Storage...' : 'Clear Analysis Cache & Temporary Files'}</span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}

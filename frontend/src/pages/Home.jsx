import React, { useEffect, useState } from 'react';
import { 
  FileSearch, 
  Cpu, 
  ArrowRight, 
  ShieldCheck, 
  AlertTriangle, 
  Layers, 
  Activity,
  Bug
} from 'lucide-react';
import { getDashboardStats } from '../services/api';

export default function Home({ onStartAnalysis }) {
  const [stats, setStats] = useState({
    total_analyses: 0,
    benign_samples: 0,
    malicious_samples: 0,
    unknown_samples: 0,
    malware_family_distribution: {}
  });

  useEffect(() => {
    getDashboardStats()
      .then(data => setStats(data))
      .catch(() => {});
  }, []);

  return (
    <div>
      {/* Hero Section matching Top-Left of UI image */}
      <div className="hero-section">
        <div className="hero-text">
          <h1 className="hero-title">
            Malware Family <span className="hero-gradient-text">Classification</span>
          </h1>
          <p className="hero-subtitle">
            Analyze files using Static / Dynamic features with Explainable AI for better interpretability.
          </p>
        </div>

        {/* Hooded Figure & Glowing Cyber Shield Graphic */}
        <div className="hero-graphic-card">
          <div className="hero-graphic-shield">
            <Bug size={42} strokeWidth={2.2} color="#60A5FA" />
          </div>
          <div style={{ marginTop: '12px', fontSize: '11px', fontWeight: '700', letterSpacing: '0.08em', color: '#60A5FA', textTransform: 'uppercase' }}>
            Threat Shield
          </div>
        </div>
      </div>

      {/* Two Primary Action Cards matching reference image */}
      <div className="action-cards-grid">
        {/* Passive Analysis Card */}
        <div className="action-card">
          <div className="action-icon-circle">
            <FileSearch size={28} />
          </div>
          <h2 className="action-card-title">Passive Analysis</h2>
          <p className="action-card-desc">
            Check file information without running it.
          </p>
          <button 
            className="btn-primary" 
            onClick={() => onStartAnalysis('passive')}
          >
            <span>Start Passive Analysis</span>
            <ArrowRight size={16} />
          </button>
        </div>

        {/* Active Analysis Card */}
        <div className="action-card">
          <div className="action-icon-circle" style={{ background: 'rgba(139, 92, 246, 0.12)', borderColor: 'rgba(139, 92, 246, 0.25)', color: '#A78BFA' }}>
            <Cpu size={28} />
          </div>
          <h2 className="action-card-title">Active Analysis</h2>
          <p className="action-card-desc">
            Run the file in a safe sandbox environment.
          </p>
          <button 
            className="btn-primary" 
            onClick={() => onStartAnalysis('active')}
          >
            <span>Start Active Analysis</span>
            <ArrowRight size={16} />
          </button>
        </div>
      </div>

      {/* Real-time Telemetry Metrics */}
      <div className="glass-card" style={{ padding: '24px 28px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Activity size={18} color="var(--accent-blue)" />
            <h3 style={{ fontSize: '16px', fontWeight: '700', color: '#FFFFFF' }}>Engine Telemetry Overview</h3>
          </div>
          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Live Database Sync</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
          <div style={{ background: '#0D111A', border: '1px solid var(--card-border)', borderRadius: '14px', padding: '16px' }}>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '6px' }}>Total Scanned</div>
            <div style={{ fontSize: '24px', fontWeight: '800', color: '#FFFFFF' }}>{stats.total_analyses}</div>
          </div>
          <div style={{ background: '#0D111A', border: '1px solid var(--card-border)', borderRadius: '14px', padding: '16px' }}>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '6px' }}>Benign Files</div>
            <div style={{ fontSize: '24px', fontWeight: '800', color: '#10B981' }}>{stats.benign_samples}</div>
          </div>
          <div style={{ background: '#0D111A', border: '1px solid var(--card-border)', borderRadius: '14px', padding: '16px' }}>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '6px' }}>Malicious Identified</div>
            <div style={{ fontSize: '24px', fontWeight: '800', color: '#EF4444' }}>{stats.malicious_samples}</div>
          </div>
          <div style={{ background: '#0D111A', border: '1px solid var(--card-border)', borderRadius: '14px', padding: '16px' }}>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '6px' }}>Malware Families</div>
            <div style={{ fontSize: '24px', fontWeight: '800', color: '#8B5CF6' }}>
              {Object.keys(stats.malware_family_distribution).length}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

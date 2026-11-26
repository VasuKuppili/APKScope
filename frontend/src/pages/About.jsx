import React from 'react';
import { BookOpen, ShieldAlert, Cpu, Sparkles, Database } from 'lucide-react';

export default function About() {
  return (
    <div>
      <div style={{ marginBottom: '28px' }}>
        <h1 style={{ fontSize: '28px', fontWeight: '800', color: '#FFFFFF', marginBottom: '6px' }}>
          About the Platform
        </h1>
        <p style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>
          Android Malware Family Classification using Static & Dynamic Features via Explainable AI with STIX/TAXII Threat Sharing.
        </p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <div className="glass-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '14px' }}>
            <BookOpen size={20} color="var(--accent-blue)" />
            <h3 style={{ fontSize: '18px', fontWeight: '700', color: '#FFFFFF' }}>Research Framework</h3>
          </div>
          <p style={{ fontSize: '14px', color: '#D1D5DB', lineHeight: '1.6' }}>
            Developed from the literature survey and research framework by <strong>Vasu Kuppili</strong>, this application 
            transcends conventional binary detection (benign vs. malicious) by executing multi-class family identification 
            (Trojan-Banker, Ransomware, Adware, Spyware, Dropper). Predictions are accompanied by SHAP local feature attributions 
            and standardized OASIS STIX 2.1 threat intelligence bundles ready for TAXII 2.1 exchange.
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
          <div className="glass-card">
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '14px' }}>
              <Cpu size={20} color="var(--accent-purple)" />
              <h3 style={{ fontSize: '16px', fontWeight: '700', color: '#FFFFFF' }}>Machine Learning & XAI</h3>
            </div>
            <ul style={{ paddingLeft: '18px', fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '1.8' }}>
              <li>Trained on Drebin & CICInvesAndMal2019-compatible feature schemas.</li>
              <li>69 multi-dimensional static and dynamic feature vectors.</li>
              <li>TreeExplainer SHAP attribution computes positive/negative weights.</li>
              <li>Calibrated confidence score with Unknown/Unclassified fallback.</li>
            </ul>
          </div>

          <div className="glass-card">
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '14px' }}>
              <Sparkles size={20} color="#FBBF24" />
              <h3 style={{ fontSize: '16px', fontWeight: '700', color: '#FFFFFF' }}>GenAI Threat Intelligence</h3>
            </div>
            <ul style={{ paddingLeft: '18px', fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '1.8' }}>
              <li>Integrated Google GenAI Python SDK (Gemini).</li>
              <li>Synthesizes technical evidence into human-readable analyst briefs.</li>
              <li>Strict boundary: Gemini explains model evidence, it does NOT classify.</li>
              <li>Zero raw APK binaries or credentials transmitted externally.</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}

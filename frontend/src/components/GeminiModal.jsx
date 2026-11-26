import React from 'react';
import { Sparkles, X, Copy, Check, AlertCircle } from 'lucide-react';

export default function GeminiModal({ isOpen, onClose, explanation, loading, error, record }) {
  const [copied, setCopied] = React.useState(false);

  if (!isOpen) return null;

  const handleCopy = () => {
    if (explanation) {
      navigator.clipboard.writeText(explanation);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" style={{ width: '640px' }} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ width: '36px', height: '36px', borderRadius: '10px', background: 'radial-gradient(circle, #8B5CF6 0%, #3B82F6 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#FFF' }}>
              <Sparkles size={18} />
            </div>
            <div>
              <h3 style={{ fontSize: '18px', fontWeight: '700', color: '#FFFFFF' }}>Gemini Executive Explanation</h3>
              <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                Natural-language threat report derived from ML classification & SHAP evidence
              </p>
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        {loading ? (
          <div style={{ padding: '40px 20px', textAlign: 'center' }}>
            <div style={{ display: 'inline-block', width: '36px', height: '36px', border: '3px solid rgba(139, 92, 246, 0.2)', borderTopColor: '#8B5CF6', borderRadius: '50%', animation: 'spin 1s linear infinite' }} />
            <p style={{ marginTop: '16px', color: 'var(--text-secondary)', fontSize: '14px' }}>
              Synthesizing analysis evidence with Google GenAI...
            </p>
          </div>
        ) : error ? (
          <div style={{ background: 'var(--status-malicious-bg)', border: '1px solid var(--status-malicious-border)', borderRadius: '12px', padding: '16px', color: '#F87171', fontSize: '13px', display: 'flex', gap: '10px' }}>
            <AlertCircle size={20} />
            <div>
              <div style={{ fontWeight: '600', marginBottom: '4px' }}>Explanation Unavailable</div>
              <div>{error}</div>
            </div>
          </div>
        ) : (
          <div>
            <div style={{ 
              background: '#0D111A', 
              border: '1px solid var(--card-border)', 
              borderRadius: '16px', 
              padding: '20px', 
              fontSize: '14px', 
              lineHeight: '1.6', 
              color: '#E5E7EB',
              maxHeight: '380px',
              overflowY: 'auto',
              whiteSpace: 'pre-wrap'
            }}>
              {explanation}
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '20px' }}>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                Explains existing analysis results without altering classification.
              </span>
              <div style={{ display: 'flex', gap: '12px' }}>
                <button className="btn-secondary" onClick={handleCopy} style={{ gap: '6px' }}>
                  {copied ? <Check size={16} color="#10B981" /> : <Copy size={16} />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
                <button className="btn-primary" onClick={onClose}>
                  Done
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

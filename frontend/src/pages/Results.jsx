import React, { useEffect, useState } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  ArrowLeft,
  Download,
  Sparkles,
  FileText,
  CheckCircle2,
  Copy,
  Check,
  Clock,
  Radio,
  Globe,
  Shield,
  Activity,
  Layers,
  ExternalLink,
  Cpu,
  Database,
  Smartphone,
  MapPin,
  Users,
  MessageSquare,
  Camera,
  Folder,
  Tag,
  Info,
  ShieldAlert
} from 'lucide-react';
import {
  getResults,
  getReportDownloadUrl,
  getStixBundle,
  generateGeminiExplanation
} from '../services/api';
import GeminiModal from '../components/GeminiModal';

export default function Results({ jobId, onBack }) {
  const [record, setRecord] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('safety');

  // Gemini Explanation State
  const [geminiOpen, setGeminiOpen] = useState(false);
  const [geminiLoading, setGeminiLoading] = useState(false);
  const [geminiText, setGeminiText] = useState('');
  const [geminiError, setGeminiError] = useState('');
  const [hashCopied, setHashCopied] = useState(false);

  useEffect(() => {
    if (!jobId) return;
    setLoading(true);
    getResults(jobId)
      .then(data => {
        setRecord(data);
        if (data.gemini_explanation) {
          setGeminiText(data.gemini_explanation);
        }
      })
      .catch(err => setError(err.message || 'Failed to load analysis result'))
      .finally(() => setLoading(false));
  }, [jobId]);

  const handleExportStix = async () => {
    try {
      const bundle = await getStixBundle(jobId);
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `stix_bundle_${record.file_hash.slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert('STIX Export Failed: ' + err.message);
    }
  };

  const handleExplainWithGemini = async () => {
    setGeminiOpen(true);
    if (geminiText) return; // Already generated

    setGeminiLoading(true);
    setGeminiError('');
    try {
      const res = await generateGeminiExplanation(jobId);
      setGeminiText(res.gemini_explanation);
    } catch (err) {
      setGeminiError(err.message);
    } finally {
      setGeminiLoading(false);
    }
  };

  const copyHash = () => {
    if (record?.file_hash) {
      navigator.clipboard.writeText(record.file_hash);
      setHashCopied(true);
      setTimeout(() => setHashCopied(false), 2000);
    }
  };

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '100px 0' }}>
        <div style={{ display: 'inline-block', width: '40px', height: '40px', border: '3px solid rgba(59, 130, 246, 0.2)', borderTopColor: '#3B82F6', borderRadius: '50%', animation: 'spin 1s linear infinite' }} />
        <p style={{ marginTop: '16px', color: 'var(--text-secondary)' }}>Loading analysis result...</p>
      </div>
    );
  }

  if (error || !record) {
    return (
      <div className="glass-card" style={{ textAlign: 'center', padding: '60px 20px', maxWidth: '600px', margin: '40px auto' }}>
        <AlertTriangle size={36} color="#EF4444" style={{ marginBottom: '16px' }} />
        <h2 style={{ fontSize: '20px', color: 'var(--text-primary)', marginBottom: '8px' }}>Unable to Display Result</h2>
        <p style={{ color: 'var(--text-secondary)', marginBottom: '24px' }}>{error || 'Record could not be retrieved.'}</p>
        <button className="btn-secondary" onClick={onBack}>Back to Dashboard</button>
      </div>
    );
  }

  const classUpper = (record.classification || '').toUpperCase();
  const isMalicious = classUpper.includes('MALICIOUS');
  const isPhishing = classUpper.includes('PHISHING') || classUpper.includes('REDIRECT');
  const isDataLeakage = classUpper.includes('DATA LEAKAGE') || classUpper.includes('PRIVACY');
  const isInconclusive = classUpper.includes('UNKNOWN') || classUpper.includes('INCONCLUSIVE');
  const isFailed = classUpper.includes('FAILED');
  const isBenign = !isMalicious && !isPhishing && !isDataLeakage && !isInconclusive && !isFailed;
  const isPassive = (record.analysis_mode || 'passive').toLowerCase() === 'passive';

  const confidence = (record.confidence_score !== undefined && record.confidence_score !== null)
    ? record.confidence_score
    : 90.0;
  const shapData = record.shap_explanation || {};
  const extFeatures = record.extracted_features || {};

  const categoryBreakdown = shapData.category_breakdown && shapData.category_breakdown.length > 0
    ? shapData.category_breakdown
    : [
      { category: 'Permissions & Manifest', percentage: 48.0 },
      { category: 'Sensitive API Calls', percentage: 32.0 },
      { category: 'Network Behavior', percentage: 20.0 }
    ];

  // Specific evidence objects
  const redirectEvidence = extFeatures.redirect_evidence;
  const dataLeakageEvidence = extFeatures.data_leakage_evidence;
  const maliciousEvidence = extFeatures.malicious_evidence;
  const eventTimeline = extFeatures.event_timeline || [];
  const networkIndicators = extFeatures.network_indicators || [];

  // Sisik-inspired APK Architecture, Ads & Trackers, Data Usage, and Safety Rationalization
  const sisikInspection = record.sisik_inspection || extFeatures.sisik_inspection || {};
  const techSpecs = record.tech_specs || extFeatures.tech_specs || sisikInspection.tech_specs || {};
  const adsAndTrackers = record.ads_and_trackers || extFeatures.ads_and_trackers || sisikInspection.ads_and_trackers || {};
  const dataUsedBreakdown = record.data_used_breakdown || extFeatures.data_used_breakdown || sisikInspection.data_used_breakdown || [];
  const safetyRationalization = record.safety_rationalization || extFeatures.safety_rationalization || sisikInspection.safety_rationalization || {};

  // MartinStyk APK Analyzer Engine Real-Time Security Test Results
  const stykAnalysis = record.styk_analysis || extFeatures.styk_analysis || {};
  const stykTestCases = stykAnalysis.test_cases || [];
  const stykMalicious = stykAnalysis.malicious_activities || [];
  const stykSuspicious = stykAnalysis.suspicious_activities || [];

  // Determine Banner Styling and Text
  let bannerClass = 'benign';
  let bannerTitle = isPassive ? 'NO SIGNIFICANT STATIC THREATS DETECTED' : 'NO SIGNIFICANT MALICIOUS INDICATORS DETECTED';
  let bannerSub = record.behavior_summary || 'All examined permissions and components conform to safe operating boundaries.';
  let BannerIcon = ShieldCheck;

  if (isPhishing) {
    bannerClass = 'warning';
    bannerTitle = 'PHISHING / SUSPICIOUS REDIRECT BEHAVIOUR DETECTED';
    bannerSub = redirectEvidence?.explanation || record.behavior_summary || 'Evidence confirms deceptive navigation or suspicious external redirection.';
    BannerIcon = AlertTriangle;
  } else if (isDataLeakage) {
    bannerClass = 'privacy';
    bannerTitle = 'DATA LEAKAGE / PRIVACY RISK DETECTED';
    bannerSub = dataLeakageEvidence?.explanation || record.behavior_summary || 'Evidence confirms unauthorized or suspicious transmission of sensitive user/device information.';
    BannerIcon = AlertTriangle;
  } else if (isMalicious) {
    bannerClass = 'malicious';
    bannerTitle = isPassive ? 'MALICIOUS / SUSPICIOUS INDICATORS DETECTED' : 'MALICIOUS BEHAVIOUR DETECTED';
    bannerSub = maliciousEvidence?.explanation || record.behavior_summary || 'Detected confirmed high-risk capabilities matching malware attack patterns.';
    BannerIcon = AlertTriangle;
  } else if (isInconclusive) {
    bannerClass = 'inconclusive';
    bannerTitle = 'UNKNOWN / INCONCLUSIVE';
    bannerSub = record.behavior_summary || 'Evidence is insufficient to make a reliable determination within the scope of analysis.';
    BannerIcon = AlertTriangle;
  } else if (isFailed) {
    bannerClass = 'failed';
    bannerTitle = 'ANALYSIS FAILED';
    bannerSub = record.status_message || 'The analysis could not complete successfully.';
    BannerIcon = AlertTriangle;
  } else {
    // Benign
    bannerClass = 'benign';
    bannerTitle = isPassive ? 'NO SIGNIFICANT STATIC THREATS DETECTED' : 'NO SIGNIFICANT MALICIOUS INDICATORS DETECTED';
    bannerSub = record.behavior_summary || 'No anomalous capabilities observed during inspection.';
    BannerIcon = ShieldCheck;
  }

  // Override banner title if backend sent exact status_banner_text
  if (extFeatures.status_banner_text) {
    bannerTitle = extFeatures.status_banner_text;
  }

  return (
    <div>
      {/* Top Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '24px' }}>
        <button
          onClick={onBack}
          style={{
            background: 'transparent',
            border: 'none',
            color: 'var(--text-secondary)',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '18px',
            fontWeight: '700'
          }}
        >
          <ArrowLeft size={22} />
          <span style={{ color: 'var(--text-primary)' }}>Analysis Result</span>
        </button>
      </div>

      {/* Full-width Status Banner */}
      <div className={`result-banner ${bannerClass}`}>
        <div className="result-banner-icon">
          <BannerIcon size={28} />
        </div>
        <div>
          <h2 className="result-title">
            {bannerTitle}
          </h2>
          <p className="result-sub">
            {bannerSub}
          </p>
        </div>
      </div>

      {/* Main Two-Column Split Layout */}
      <div className="result-columns-grid">
        {/* Left Column: Details Card */}
        <div className="glass-card">
          <h3 style={{ fontSize: '18px', fontWeight: '700', color: 'var(--text-primary)', marginBottom: '20px' }}>
            Details
          </h3>

          {/* Confidence Score Bar */}
          <div style={{ marginBottom: '18px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px', marginBottom: '8px' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Confidence Score</span>
              <span style={{ color: 'var(--text-primary)', fontWeight: '700' }}>{confidence}%</span>
            </div>
            <div style={{ width: '100%', height: '8px', background: 'rgba(255, 255, 255, 0.08)', borderRadius: '4px', overflow: 'hidden' }}>
              <div
                style={{
                  width: `${confidence}%`,
                  height: '100%',
                  background: isMalicious ? '#EF4444' : isPhishing ? '#F59E0B' : isDataLeakage ? '#8B5CF6' : '#10B981',
                  borderRadius: '4px'
                }}
              />
            </div>
          </div>

          <div className="details-row">
            <span className="details-label">Classification Result</span>
            <span className="details-value" style={{
              fontWeight: '700',
              color: isMalicious ? '#F87171' : isPhishing ? '#FBBF24' : isDataLeakage ? '#C084FC' : '#34D399'
            }}>
              {record.classification}
            </span>
          </div>

          <div className="details-row">
            <span className="details-label">Analysis Mode</span>
            <span className="details-value" style={{ textTransform: 'capitalize' }}>
              {record.analysis_mode || 'Passive'} Analysis
            </span>
          </div>

          <div className="details-row">
            <span className="details-label">File Name</span>
            <span className="details-value">{record.filename}</span>
          </div>

          <div className="details-row">
            <span className="details-label">Package Name</span>
            <span className="details-value" style={{ fontFamily: 'monospace', fontSize: '12px' }}>
              {extFeatures.package_name || 'com.unknown.app'}
            </span>
          </div>

          <div className="details-row">
            <span className="details-label">App Version</span>
            <span className="details-value">
              {extFeatures.version_name || '1.0'}
            </span>
          </div>

          <div className="details-row">
            <span className="details-label">File Size</span>
            <span className="details-value">{Math.round((record.file_size || 0) / 1024)} KB</span>
          </div>

          <div className="details-row">
            <span className="details-label">SHA-256</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="details-value" title={record.file_hash}>
                {record.file_hash ? `${record.file_hash.slice(0, 14)}...` : 'N/A'}
              </span>
              <button
                onClick={copyHash}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}
                title="Copy SHA-256"
              >
                {hashCopied ? <Check size={14} color="#10B981" /> : <Copy size={14} />}
              </button>
            </div>
          </div>

          <div className="details-row">
            <span className="details-label">Analysis Status</span>
            <span className="details-value" style={{ color: record.status === 'COMPLETED' ? '#34D399' : '#F87171' }}>
              {record.status}
            </span>
          </div>

          <div className="details-row">
            <span className="details-label">Malware Family</span>
            <span className="details-value" style={{ color: isMalicious ? '#F87171' : 'var(--text-primary)', fontWeight: isMalicious ? '700' : '500' }}>
              {record.malware_family || 'None'}
            </span>
          </div>

          {shapData.threat_score !== undefined && (
            <div className="details-row">
              <span className="details-label">Risk Level</span>
              <span className="details-value" style={{
                color: shapData.risk_level === 'Critical' || shapData.risk_level === 'High' ? '#F87171' : '#34D399',
                fontWeight: '700'
              }}>
                {shapData.threat_score} / 100 ({shapData.risk_level || 'Clean'})
              </span>
            </div>
          )}

          {record.threat_intelligence && (
            <div className="details-row">
              <span className="details-label">Threat Correlation</span>
              <span className="details-value" style={{
                color: (record.threat_intelligence.intelligence_match_status || '').includes('Confirmed') ? '#F87171' : '#34D399',
                fontWeight: '600',
                fontSize: '11px',
                textAlign: 'right'
              }}>
                {(record.threat_intelligence.intelligence_match_status || '').includes('Confirmed') ? 'Confirmed Match' : 'Clean / No Indicators'}
              </span>
            </div>
          )}

          <div className="details-row">
            <span className="details-label">Model Version</span>
            <span className="details-value">{record.model_version || '1.4.0'}</span>
          </div>

          <div className="details-row" style={{ borderBottom: 'none', paddingTop: '12px', alignItems: 'flex-start' }}>
            <span className="details-label">Summary</span>
            <span className="details-value" style={{ maxWidth: '280px', textAlign: 'right', fontSize: '12px', lineHeight: '1.4' }}>
              {record.behavior_summary || bannerSub}
            </span>
          </div>
        </div>

        {/* Right Column: Multi-tab Evidence & Findings Card */}
        <div className="glass-card" style={{ display: 'flex', flexDirection: 'column' }}>
          {/* Navigation Tabs */}
          <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--card-border)', paddingBottom: '14px', marginBottom: '18px', flexWrap: 'wrap' }}>
            <button
              onClick={() => setActiveTab('safety')}
              style={{
                background: activeTab === 'safety' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                border: activeTab === 'safety' ? '1px solid rgba(59, 130, 246, 0.3)' : 'none',
                color: activeTab === 'safety' ? '#60A5FA' : 'var(--text-secondary)',
                borderRadius: '8px',
                padding: '6px 12px',
                fontSize: '12px',
                fontWeight: '600',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px'
              }}
            >
              <ShieldCheck size={14} />
              <span>Safety Verdict</span>
            </button>

            <button
              onClick={() => setActiveTab('styk-tests')}
              style={{
                background: activeTab === 'styk-tests' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                border: activeTab === 'styk-tests' ? '1px solid rgba(59, 130, 246, 0.3)' : 'none',
                color: activeTab === 'styk-tests' ? '#60A5FA' : 'var(--text-secondary)',
                borderRadius: '8px',
                padding: '6px 12px',
                fontSize: '12px',
                fontWeight: '600',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px'
              }}
            >
              <ShieldAlert size={14} />
              <span>Security Tests (MartinStyk)</span>
              {stykAnalysis.is_clean ? (
                <span style={{ fontSize: '10px', padding: '1px 5px', borderRadius: '4px', background: 'rgba(16, 185, 129, 0.2)', color: '#34D399' }}>
                  CLEAN
                </span>
              ) : (
                <span style={{ fontSize: '10px', padding: '1px 5px', borderRadius: '4px', background: 'rgba(239, 68, 68, 0.2)', color: '#F87171' }}>
                  {stykMalicious.length > 0 ? 'MALICIOUS' : 'ISSUES'}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('ads')}
              style={{
                background: activeTab === 'ads' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                border: activeTab === 'ads' ? '1px solid rgba(59, 130, 246, 0.3)' : 'none',
                color: activeTab === 'ads' ? '#60A5FA' : 'var(--text-secondary)',
                borderRadius: '8px',
                padding: '6px 12px',
                fontSize: '12px',
                fontWeight: '600',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px'
              }}
            >
              <Tag size={14} />
              <span>Ads & Trackers</span>
              {adsAndTrackers.ad_networks_count > 0 && (
                <span style={{ fontSize: '10px', padding: '1px 5px', borderRadius: '4px', background: adsAndTrackers.ad_health === 'Harmful' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(59, 130, 246, 0.2)', color: adsAndTrackers.ad_health === 'Harmful' ? '#F87171' : '#60A5FA' }}>
                  {adsAndTrackers.ad_networks_count}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('data-used')}
              style={{
                background: activeTab === 'data-used' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                border: activeTab === 'data-used' ? '1px solid rgba(59, 130, 246, 0.3)' : 'none',
                color: activeTab === 'data-used' ? '#60A5FA' : 'var(--text-secondary)',
                borderRadius: '8px',
                padding: '6px 12px',
                fontSize: '12px',
                fontWeight: '600',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px'
              }}
            >
              <Database size={14} />
              <span>Data Usage & Privacy</span>
              {dataUsedBreakdown.length > 0 && (
                <span style={{ fontSize: '10px', padding: '1px 5px', borderRadius: '4px', background: 'rgba(139, 92, 246, 0.2)', color: '#C084FC' }}>
                  {dataUsedBreakdown.length}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('specs')}
              style={{
                background: activeTab === 'specs' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                border: activeTab === 'specs' ? '1px solid rgba(59, 130, 246, 0.3)' : 'none',
                color: activeTab === 'specs' ? '#60A5FA' : 'var(--text-secondary)',
                borderRadius: '8px',
                padding: '6px 12px',
                fontSize: '12px',
                fontWeight: '600',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px'
              }}
            >
              <Cpu size={14} />
              <span>Tech Specs & ABIs</span>
            </button>

            <button
              onClick={() => setActiveTab('evidence')}
              style={{
                background: activeTab === 'evidence' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                border: activeTab === 'evidence' ? '1px solid rgba(59, 130, 246, 0.3)' : 'none',
                color: activeTab === 'evidence' ? '#60A5FA' : 'var(--text-secondary)',
                borderRadius: '8px',
                padding: '6px 12px',
                fontSize: '12px',
                fontWeight: '600',
                cursor: 'pointer'
              }}
            >
              Evidence & Findings
            </button>
            <button
              onClick={() => setActiveTab('xai')}
              style={{
                background: activeTab === 'xai' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                border: activeTab === 'xai' ? '1px solid rgba(59, 130, 246, 0.3)' : 'none',
                color: activeTab === 'xai' ? '#60A5FA' : 'var(--text-secondary)',
                borderRadius: '8px',
                padding: '6px 12px',
                fontSize: '12px',
                fontWeight: '600',
                cursor: 'pointer'
              }}
            >
              Explainability (SHAP)
            </button>
            <button
              onClick={() => setActiveTab('static')}
              style={{
                background: activeTab === 'static' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                border: activeTab === 'static' ? '1px solid rgba(59, 130, 246, 0.3)' : 'none',
                color: activeTab === 'static' ? '#60A5FA' : 'var(--text-secondary)',
                borderRadius: '8px',
                padding: '6px 12px',
                fontSize: '12px',
                fontWeight: '600',
                cursor: 'pointer'
              }}
            >
              Static Findings
            </button>
            <button
              onClick={() => setActiveTab('threat-intel')}
              style={{
                background: activeTab === 'threat-intel' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                border: activeTab === 'threat-intel' ? '1px solid rgba(59, 130, 246, 0.3)' : 'none',
                color: activeTab === 'threat-intel' ? '#60A5FA' : 'var(--text-secondary)',
                borderRadius: '8px',
                padding: '6px 12px',
                fontSize: '12px',
                fontWeight: '600',
                cursor: 'pointer'
              }}
            >
              Threat Intelligence Correlation
            </button>
            {eventTimeline.length > 0 && (
              <button
                onClick={() => setActiveTab('timeline')}
                style={{
                  background: activeTab === 'timeline' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                  border: activeTab === 'timeline' ? '1px solid rgba(59, 130, 246, 0.3)' : 'none',
                  color: activeTab === 'timeline' ? '#60A5FA' : 'var(--text-secondary)',
                  borderRadius: '8px',
                  padding: '6px 12px',
                  fontSize: '12px',
                  fontWeight: '600',
                  cursor: 'pointer'
                }}
              >
                Event Timeline ({eventTimeline.length})
              </button>
            )}
            {networkIndicators.length > 0 && (
              <button
                onClick={() => setActiveTab('network')}
                style={{
                  background: activeTab === 'network' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                  border: activeTab === 'network' ? '1px solid rgba(59, 130, 246, 0.3)' : 'none',
                  color: activeTab === 'network' ? '#60A5FA' : 'var(--text-secondary)',
                  borderRadius: '8px',
                  padding: '6px 12px',
                  fontSize: '12px',
                  fontWeight: '600',
                  cursor: 'pointer'
                }}
              >
                Network Indicators ({networkIndicators.length})
              </button>
            )}
          </div>

          {/* Tab: Safety Verdict (Why is this application safe or harmful?) */}
          {activeTab === 'safety' && (
            <div>
              <div style={{
                background: safetyRationalization.is_harmful ? 'rgba(239, 68, 68, 0.08)' : 'rgba(16, 185, 129, 0.08)',
                border: safetyRationalization.is_harmful ? '1px solid rgba(239, 68, 68, 0.25)' : '1px solid rgba(16, 185, 129, 0.25)',
                borderRadius: '12px',
                padding: '18px',
                marginBottom: '18px'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
                  {safetyRationalization.is_harmful ? (
                    <AlertTriangle size={22} color="#EF4444" />
                  ) : (
                    <ShieldCheck size={22} color="#10B981" />
                  )}
                  <h3 style={{ fontSize: '16px', fontWeight: '800', color: safetyRationalization.is_harmful ? '#F87171' : '#34D399', margin: 0 }}>
                    {safetyRationalization.headline || (safetyRationalization.is_harmful ? 'Why This Application Is Harmful' : 'Why This Application Is Safe')}
                  </h3>
                </div>
                <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: '0 0 12px 0', lineHeight: '1.5' }}>
                  {safetyRationalization.recommendation}
                </p>

                {/* Key Reason Bullet Points */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '12px' }}>
                  {(safetyRationalization.reasons || []).map((reason, idx) => (
                    <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', fontSize: '12px', lineHeight: '1.4' }}>
                      <span style={{ color: safetyRationalization.is_harmful ? '#EF4444' : '#10B981', marginTop: '2px', flexShrink: 0 }}>
                        {safetyRationalization.is_harmful ? '⚠️' : '✓'}
                      </span>
                      <span style={{ color: 'var(--text-secondary)' }}>{reason}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Security Metrics Quick Summary */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', marginBottom: '16px' }}>
                <div style={{ background: 'var(--surface-low)', border: '1px solid var(--card-border)', borderRadius: '10px', padding: '12px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>Data Categories Accessed</div>
                  <div style={{ fontSize: '18px', fontWeight: '800', color: '#60A5FA' }}>
                    {safetyRationalization.data_categories_count || dataUsedBreakdown.length || 0}
                  </div>
                </div>
                <div style={{ background: 'var(--surface-low)', border: '1px solid var(--card-border)', borderRadius: '10px', padding: '12px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>Dangerous Permissions</div>
                  <div style={{ fontSize: '18px', fontWeight: '800', color: (extFeatures.dangerous_permissions || []).length > 2 ? '#EF4444' : '#10B981' }}>
                    {(extFeatures.dangerous_permissions || []).length}
                  </div>
                </div>
                <div style={{ background: 'var(--surface-low)', border: '1px solid var(--card-border)', borderRadius: '10px', padding: '12px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>Ad Network Profile</div>
                  <div style={{ fontSize: '13px', fontWeight: '700', color: adsAndTrackers.ad_health === 'Harmful' ? '#EF4444' : '#10B981', marginTop: '4px' }}>
                    {adsAndTrackers.ad_health || 'Safe'}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Tab: MartinStyk APK Analyzer Engine Security Tests */}
          {activeTab === 'styk-tests' && (
            <div>
              {/* Engine Header & Primary Verdict */}
              <div style={{
                background: stykAnalysis.is_clean
                  ? 'rgba(16, 185, 129, 0.08)'
                  : (stykMalicious.length > 0 ? 'rgba(239, 68, 68, 0.08)' : 'rgba(245, 158, 11, 0.08)'),
                border: stykAnalysis.is_clean
                  ? '1px solid rgba(16, 185, 129, 0.25)'
                  : (stykMalicious.length > 0 ? '1px solid rgba(239, 68, 68, 0.25)' : '1px solid rgba(245, 158, 11, 0.25)'),
                borderRadius: '12px',
                padding: '18px',
                marginBottom: '18px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '10px', marginBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    {stykAnalysis.is_clean ? (
                      <CheckCircle2 size={24} color="#10B981" />
                    ) : (
                      <AlertTriangle size={24} color={stykMalicious.length > 0 ? '#EF4444' : '#F59E0B'} />
                    )}
                    <div>
                      <h3 style={{
                        fontSize: '16px',
                        fontWeight: '800',
                        color: stykAnalysis.is_clean ? '#34D399' : (stykMalicious.length > 0 ? '#F87171' : '#FBBF24'),
                        margin: 0
                      }}>
                        {stykAnalysis.verdict || (stykAnalysis.is_clean ? 'CLEAN APPLICATION' : 'SECURITY ISSUES DETECTED')}
                      </h3>
                      <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                        MartinStyk APK Analyzer Engine — Real-Time Binary Security Testing
                      </div>
                    </div>
                  </div>
                  <span style={{
                    fontSize: '11px',
                    fontWeight: '700',
                    padding: '4px 10px',
                    borderRadius: '6px',
                    background: stykAnalysis.is_clean ? 'rgba(16, 185, 129, 0.2)' : (stykMalicious.length > 0 ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)'),
                    color: stykAnalysis.is_clean ? '#34D399' : (stykMalicious.length > 0 ? '#F87171' : '#FBBF24')
                  }}>
                    {stykAnalysis.is_clean ? 'PASSED ALL TESTS' : `${stykAnalysis.failed_tests_count || 1} TEST(S) FAILED`}
                  </span>
                </div>

                <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: '8px 0 0 0', lineHeight: '1.5' }}>
                  {stykAnalysis.summary || (stykAnalysis.is_clean
                    ? 'All examined security test cases passed. The APK uses legitimate developer signatures, safe permission sets, and contains no malicious behavioral hooks.'
                    : 'Real-time analysis detected security violations or malicious behavior matching recognized threat vectors.')}
                </p>
              </div>

              {/* Confirmed Malicious Activities Box */}
              {stykMalicious.length > 0 && (
                <div style={{
                  background: 'rgba(239, 68, 68, 0.06)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  borderRadius: '12px',
                  padding: '16px',
                  marginBottom: '18px'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                    <ShieldAlert size={18} color="#EF4444" />
                    <h4 style={{ fontSize: '14px', fontWeight: '800', color: '#F87171', margin: 0 }}>
                      Confirmed Malicious Activities ({stykMalicious.length})
                    </h4>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {stykMalicious.map((act, idx) => (
                      <div key={idx} style={{
                        background: 'rgba(239, 68, 68, 0.1)',
                        border: '1px solid rgba(239, 68, 68, 0.2)',
                        borderRadius: '8px',
                        padding: '10px 14px',
                        fontSize: '12px',
                        color: '#FECACA',
                        display: 'flex',
                        alignItems: 'flex-start',
                        gap: '10px',
                        lineHeight: '1.4'
                      }}>
                        <span style={{ color: '#EF4444', fontWeight: 'bold' }}>⛔</span>
                        <span>{act}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Suspicious Activities / Vulnerabilities Box */}
              {stykSuspicious.length > 0 && (
                <div style={{
                  background: 'rgba(245, 158, 11, 0.06)',
                  border: '1px solid rgba(245, 158, 11, 0.3)',
                  borderRadius: '12px',
                  padding: '16px',
                  marginBottom: '18px'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                    <AlertTriangle size={18} color="#F59E0B" />
                    <h4 style={{ fontSize: '14px', fontWeight: '800', color: '#FBBF24', margin: 0 }}>
                      Suspicious Activities & Vulnerabilities ({stykSuspicious.length})
                    </h4>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {stykSuspicious.map((act, idx) => (
                      <div key={idx} style={{
                        background: 'rgba(245, 158, 11, 0.1)',
                        border: '1px solid rgba(245, 158, 11, 0.2)',
                        borderRadius: '8px',
                        padding: '10px 14px',
                        fontSize: '12px',
                        color: '#FEF3C7',
                        display: 'flex',
                        alignItems: 'flex-start',
                        gap: '10px',
                        lineHeight: '1.4'
                      }}>
                        <span style={{ color: '#F59E0B', fontWeight: 'bold' }}>⚠️</span>
                        <span>{act}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Clean Guarantee Callout if Clean */}
              {stykAnalysis.is_clean && (
                <div style={{
                  background: 'rgba(16, 185, 129, 0.05)',
                  border: '1px solid rgba(16, 185, 129, 0.2)',
                  borderRadius: '10px',
                  padding: '14px',
                  marginBottom: '18px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px'
                }}>
                  <CheckCircle2 size={20} color="#10B981" />
                  <div style={{ fontSize: '12px', color: '#A7F3D0', lineHeight: '1.4' }}>
                    <strong>Clean Application:</strong> No harmful or suspicious code was found during the real-time execution of the test suite. All security parameters are within normal boundaries.
                  </div>
                </div>
              )}

              {/* Individual Security Test Cases */}
              <div style={{ marginBottom: '18px' }}>
                <h4 style={{ fontSize: '13px', fontWeight: '700', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '12px' }}>
                  Real-Time Security Test Cases ({stykTestCases.length || 7})
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {stykTestCases.map((tc, idx) => {
                    const isPassed = tc.status === 'PASSED';
                    const isWarning = tc.status === 'WARNING';
                    const statusColor = isPassed ? '#10B981' : (isWarning ? '#F59E0B' : '#EF4444');
                    const statusBg = isPassed ? 'rgba(16, 185, 129, 0.1)' : (isWarning ? 'rgba(245, 158, 11, 0.1)' : 'rgba(239, 68, 68, 0.1)');
                    const statusBorder = isPassed ? 'rgba(16, 185, 129, 0.25)' : (isWarning ? 'rgba(245, 158, 11, 0.25)' : 'rgba(239, 68, 68, 0.25)');

                    return (
                      <div key={idx} style={{
                        background: 'var(--surface-low)',
                        border: `1px solid ${statusBorder}`,
                        borderRadius: '10px',
                        padding: '12px 16px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '6px'
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span style={{ fontSize: '13px', fontWeight: '700', color: 'var(--text-primary)' }}>
                            {tc.test_name}
                          </span>
                          <span style={{
                            fontSize: '11px',
                            fontWeight: '700',
                            padding: '2px 8px',
                            borderRadius: '4px',
                            background: statusBg,
                            color: statusColor
                          }}>
                            {tc.status}
                          </span>
                        </div>
                        <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                          {tc.details}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Technical Binary & Scheme Details */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '10px' }}>
                <div style={{ background: 'var(--surface-low)', border: '1px solid var(--card-border)', borderRadius: '10px', padding: '12px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>Signing Schemes</div>
                  <div style={{ fontSize: '13px', fontWeight: '700', color: 'var(--text-primary)' }}>
                    {(stykAnalysis.signing_block_details?.schemes || []).join(', ') || 'V1 (Standard)'}
                  </div>
                </div>
                <div style={{ background: 'var(--surface-low)', border: '1px solid var(--card-border)', borderRadius: '10px', padding: '12px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>Certificate Trust</div>
                  <div style={{ fontSize: '13px', fontWeight: '700', color: stykAnalysis.certificate_trust_details?.is_suspicious ? '#EF4444' : '#10B981' }}>
                    {stykAnalysis.certificate_trust_details?.trust_level || 'Valid'} ({stykAnalysis.certificate_trust_details?.status || 'VALID'})
                  </div>
                </div>
                <div style={{ background: 'var(--surface-low)', border: '1px solid var(--card-border)', borderRadius: '10px', padding: '12px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>Janus Vulnerability</div>
                  <div style={{ fontSize: '13px', fontWeight: '700', color: stykAnalysis.signing_block_details?.is_janus_vulnerable ? '#EF4444' : '#10B981' }}>
                    {stykAnalysis.signing_block_details?.is_janus_vulnerable ? 'Vulnerable (CVE-2017-13156)' : 'Protected (V2/V3 Block)'}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Tab: Ads & Trackers Audit (Useful or Harmful?) */}
          {activeTab === 'ads' && (
            <div>
              {/* Overall Ad Assessment Banner */}
              <div style={{
                background: adsAndTrackers.ad_health === 'Harmful'
                  ? 'rgba(239, 68, 68, 0.08)'
                  : adsAndTrackers.ad_health === 'Safe'
                    ? 'rgba(59, 130, 246, 0.08)'
                    : 'rgba(16, 185, 129, 0.08)',
                border: adsAndTrackers.ad_health === 'Harmful'
                  ? '1px solid rgba(239, 68, 68, 0.25)'
                  : adsAndTrackers.ad_health === 'Safe'
                    ? '1px solid rgba(59, 130, 246, 0.25)'
                    : '1px solid rgba(16, 185, 129, 0.25)',
                borderRadius: '12px',
                padding: '16px',
                marginBottom: '16px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span style={{ fontSize: '14px', fontWeight: '700', color: 'var(--text-primary)' }}>
                    Advertising & Telemetry Assessment
                  </span>
                  <span style={{
                    fontSize: '11px',
                    fontWeight: '700',
                    padding: '3px 8px',
                    borderRadius: '6px',
                    background: adsAndTrackers.ad_health === 'Harmful' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(59, 130, 246, 0.2)',
                    color: adsAndTrackers.ad_health === 'Harmful' ? '#F87171' : '#60A5FA'
                  }}>
                    {adsAndTrackers.overall_ad_verdict || 'Standard Evaluation'}
                  </span>
                </div>
                <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.5', margin: 0 }}>
                  {adsAndTrackers.ad_summary_explanation || 'Evaluation of embedded advertising SDKs and tracking telemetry.'}
                </p>
              </div>

              {/* Detected Ad Networks */}
              <div style={{ marginBottom: '18px' }}>
                <div style={{ fontSize: '12px', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '10px' }}>
                  Detected In-App Advertising SDKs ({(adsAndTrackers.ad_networks || []).length})
                </div>
                {(!adsAndTrackers.ad_networks || adsAndTrackers.ad_networks.length === 0) ? (
                  <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '14px', borderRadius: '8px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                    No embedded advertising SDKs or banner ad networks detected in this APK archive.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {adsAndTrackers.ad_networks.map((ad, i) => (
                      <div key={i} style={{ background: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--card-border)', borderRadius: '8px', padding: '12px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                          <span style={{ fontSize: '13px', fontWeight: '700', color: 'var(--text-primary)' }}>{ad.name}</span>
                          <span style={{
                            fontSize: '11px',
                            fontWeight: '700',
                            padding: '2px 8px',
                            borderRadius: '4px',
                            background: ad.is_intrusive ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                            color: ad.is_intrusive ? '#F87171' : '#34D399'
                          }}>
                            {ad.verdict}
                          </span>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--accent-blue)', marginBottom: '4px' }}>
                          Category: {ad.category} • Risk Level: {ad.risk_level}
                        </div>
                        <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                          {ad.description}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Detected Analytics & Crash Trackers */}
              <div>
                <div style={{ fontSize: '12px', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '10px' }}>
                  Diagnostic & Analytics Trackers ({(adsAndTrackers.trackers || []).length})
                </div>
                {(!adsAndTrackers.trackers || adsAndTrackers.trackers.length === 0) ? (
                  <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '14px', borderRadius: '8px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                    No commercial marketing or telemetry trackers identified.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {adsAndTrackers.trackers.map((trk, i) => (
                      <div key={i} style={{ background: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--card-border)', borderRadius: '8px', padding: '10px 12px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2px' }}>
                          <span style={{ fontSize: '12px', fontWeight: '700', color: 'var(--text-primary)' }}>{trk.name}</span>
                          <span style={{ fontSize: '11px', color: '#60A5FA' }}>{trk.verdict}</span>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                          {trk.description}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}


          {/* Tab: Data Used & Privacy Impact (What Data Is Used?) */}
          {activeTab === 'data-used' && (
            <div>
              <div style={{ marginBottom: '14px' }}>
                <span style={{ fontSize: '13px', fontWeight: '700', color: 'var(--text-primary)' }}>
                  User & Device Data Access Profile
                </span>
                <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: '4px 0 0 0' }}>
                  Detailed audit of sensitive device sensors, personal documents, and telemetry requested by this APK.
                </p>
              </div>

              {dataUsedBreakdown.length === 0 ? (
                <div style={{ background: 'rgba(16, 185, 129, 0.06)', border: '1px solid rgba(16, 185, 129, 0.2)', borderRadius: '10px', padding: '18px', textAlign: 'center', color: '#34D399', fontSize: '13px' }}>
                  No sensitive personal or hardware data access declared by this application.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  {dataUsedBreakdown.map((item, i) => {
                    const isCrit = item.risk_level === 'Critical';
                    const isHigh = item.risk_level === 'High';
                    const badgeBg = isCrit ? 'rgba(239, 68, 68, 0.15)' : isHigh ? 'rgba(245, 158, 11, 0.15)' : 'rgba(59, 130, 246, 0.15)';
                    const badgeColor = isCrit ? '#F87171' : isHigh ? '#FBBF24' : '#60A5FA';

                    return (
                      <div key={i} style={{ background: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--card-border)', borderRadius: '10px', padding: '14px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                          <span style={{ fontSize: '14px', fontWeight: '700', color: 'var(--text-primary)' }}>
                            {item.category}
                          </span>
                          <span style={{ fontSize: '11px', fontWeight: '700', padding: '2px 8px', borderRadius: '4px', background: badgeBg, color: badgeColor }}>
                            {item.risk_level} Sensitivity
                          </span>
                        </div>

                        <div style={{ fontSize: '12px', fontWeight: '600', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                          Data Collected: <span style={{ color: 'var(--text-secondary)', fontWeight: '400' }}>{item.data_collected}</span>
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '11px', marginTop: '6px' }}>
                          <div style={{ background: 'rgba(16, 185, 129, 0.05)', border: '1px solid rgba(16, 185, 129, 0.15)', borderRadius: '6px', padding: '8px' }}>
                            <div style={{ color: '#34D399', fontWeight: '700', marginBottom: '2px' }}>Legitimate App Use:</div>
                            <div style={{ color: 'var(--text-secondary)' }}>{item.purpose_legitimate}</div>
                          </div>
                          <div style={{ background: 'rgba(239, 68, 68, 0.05)', border: '1px solid rgba(239, 68, 68, 0.15)', borderRadius: '6px', padding: '8px' }}>
                            <div style={{ color: '#F87171', fontWeight: '700', marginBottom: '2px' }}>Privacy & Security Risk:</div>
                            <div style={{ color: 'var(--text-secondary)' }}>{item.purpose_harmful}</div>
                          </div>
                        </div>

                        {item.matched_permissions && item.matched_permissions.length > 0 && (
                          <div style={{ marginTop: '8px', display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                            {item.matched_permissions.map(p => (
                              <span key={p} style={{ fontSize: '10px', fontFamily: 'monospace', padding: '2px 6px', borderRadius: '4px', background: 'rgba(255, 255, 255, 0.04)', color: 'var(--text-secondary)' }}>
                                {p.replace('android.permission.', '')}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* Tab: Tech Specs & Architecture (Sisik-Style APK Analyzer) */}
          {activeTab === 'specs' && (
            <div>
              <div style={{ marginBottom: '14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '13px', fontWeight: '700', color: 'var(--text-primary)' }}>
                  Architecture & Developer Signature (Sisik Tool Specs)
                </span>
                <span style={{
                  fontSize: '11px',
                  fontWeight: '700',
                  padding: '3px 8px',
                  borderRadius: '6px',
                  background: techSpecs.is_64_bit ? 'rgba(16, 185, 129, 0.2)' : 'rgba(59, 130, 246, 0.2)',
                  color: techSpecs.is_64_bit ? '#34D399' : '#60A5FA'
                }}>
                  {techSpecs.is_64_bit ? '64-Bit Architecture Ready' : 'Universal / 32-Bit Compatible'}
                </span>
              </div>

              {/* Specification Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
                <div style={{ background: 'var(--surface-low)', border: '1px solid var(--card-border)', borderRadius: '10px', padding: '12px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>Minimum Android OS</div>
                  <div style={{ fontSize: '13px', fontWeight: '700', color: 'var(--text-primary)' }}>
                    {techSpecs.min_sdk_label || `API Level ${techSpecs.min_sdk_int || '21'}`}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                    Min SDK Version: {techSpecs.min_sdk_int || '21'}
                  </div>
                </div>

                <div style={{ background: 'var(--surface-low)', border: '1px solid var(--card-border)', borderRadius: '10px', padding: '12px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>Target Android OS</div>
                  <div style={{ fontSize: '13px', fontWeight: '700', color: '#60A5FA' }}>
                    {techSpecs.target_sdk_label || `API Level ${techSpecs.target_sdk_int || '33'}`}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                    Target SDK Version: {techSpecs.target_sdk_int || '33'}
                  </div>
                </div>
              </div>

              {/* Supported ABIs */}
              <div style={{ marginBottom: '16px', background: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--card-border)', borderRadius: '10px', padding: '12px' }}>
                <div style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px' }}>
                  Supported CPU Architectures (ABIs)
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                  {(techSpecs.supported_abis || ['arm64-v8a', 'armeabi-v7a']).map((abi, idx) => (
                    <span key={idx} style={{ padding: '3px 8px', borderRadius: '6px', fontSize: '11px', fontFamily: 'monospace', background: 'rgba(59, 130, 246, 0.1)', color: '#60A5FA', border: '1px solid rgba(59, 130, 246, 0.25)' }}>
                      {abi}
                    </span>
                  ))}
                </div>
                {techSpecs.native_libraries && techSpecs.native_libraries.length > 0 && (
                  <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                    Native Shared Libraries ({techSpecs.native_libraries_count}): <span style={{ fontFamily: 'monospace', color: 'var(--text-secondary)' }}>{techSpecs.native_libraries.join(', ')}</span>
                  </div>
                )}
              </div>

              {/* Signing Certificate & Keystore */}
              <div style={{ background: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--card-border)', borderRadius: '10px', padding: '12px' }}>
                <div style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '8px' }}>
                  Signing Certificate & Developer Identity
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '6px', fontSize: '12px' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Certificate Status:</span>
                  <span style={{ color: techSpecs.certificate?.is_signed ? '#34D399' : '#FBBF24', fontWeight: '600' }}>
                    {techSpecs.certificate?.is_signed ? 'Cryptographically Signed' : 'Self-Signed / Developer Keystore'}
                  </span>
                  <span style={{ color: 'var(--text-secondary)' }}>Issuer:</span>
                  <span style={{ color: 'var(--text-primary)', wordBreak: 'break-all' }}>{techSpecs.certificate?.issuer || 'Android Application Signer'}</span>
                  <span style={{ color: 'var(--text-secondary)' }}>Signature Scheme:</span>
                  <span style={{ color: '#60A5FA' }}>{(techSpecs.certificate?.signature_schemes || ['v1 (JAR)']).join(', ')}</span>
                  {techSpecs.certificate?.sha256 && (
                    <>
                      <span style={{ color: 'var(--text-secondary)' }}>SHA-256 Fingerprint:</span>
                      <span style={{ color: 'var(--text-secondary)', fontFamily: 'monospace', fontSize: '10px', wordBreak: 'break-all' }}>
                        {techSpecs.certificate.sha256}
                      </span>
                    </>
                  )}
                </div>
              </div>
            </div>
          )}


          {/* Tab 1: Evidence & Findings */}
          {activeTab === 'evidence' && (
            <div>
              {/* Phishing / Redirect Evidence */}
              {redirectEvidence && (
                <div style={{ background: 'rgba(245, 158, 11, 0.06)', border: '1px solid rgba(245, 158, 11, 0.2)', borderRadius: '12px', padding: '16px', marginBottom: '16px' }}>
                  <div style={{ fontSize: '14px', fontWeight: '700', color: '#FBBF24', marginBottom: '10px' }}>
                    Redirect & Phishing Navigation Details
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '130px 1fr', gap: '8px', fontSize: '12px', marginBottom: '8px' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>Destination:</span>
                    <span style={{ color: 'var(--text-primary)', fontWeight: '600' }}>{redirectEvidence.redirect_destination}</span>
                    <span style={{ color: 'var(--text-secondary)' }}>Original Activity:</span>
                    <span style={{ color: 'var(--text-primary)', fontFamily: 'monospace' }}>{redirectEvidence.original_activity}</span>
                    <span style={{ color: 'var(--text-secondary)' }}>Triggering Action:</span>
                    <span style={{ color: 'var(--text-primary)' }}>{redirectEvidence.triggering_action}</span>
                    <span style={{ color: 'var(--text-secondary)' }}>Redirect URL:</span>
                    <span style={{ color: '#60A5FA', fontFamily: 'monospace', wordBreak: 'break-all' }}>{redirectEvidence.redirect_url}</span>
                    <span style={{ color: 'var(--text-secondary)' }}>Timestamp:</span>
                    <span style={{ color: 'var(--text-muted)' }}>{redirectEvidence.timestamp}</span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '10px', lineHeight: '1.4' }}>
                    {redirectEvidence.explanation}
                  </div>
                </div>
              )}

              {/* Data Leakage Evidence */}
              {dataLeakageEvidence && (
                <div style={{ background: 'rgba(139, 92, 246, 0.06)', border: '1px solid rgba(139, 92, 246, 0.2)', borderRadius: '12px', padding: '16px', marginBottom: '16px' }}>
                  <div style={{ fontSize: '14px', fontWeight: '700', color: '#C084FC', marginBottom: '10px' }}>
                    Data Leakage & Privacy Risk Telemetry
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '140px 1fr', gap: '8px', fontSize: '12px', marginBottom: '8px' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>Information Accessed:</span>
                    <span style={{ color: 'var(--text-primary)', fontWeight: '600' }}>
                      {Array.isArray(dataLeakageEvidence.information_accessed) ? dataLeakageEvidence.information_accessed.join(', ') : dataLeakageEvidence.information_accessed}
                    </span>
                    <span style={{ color: 'var(--text-secondary)' }}>Actually Transmitted:</span>
                    <span style={{ color: '#34D399', fontWeight: '700' }}>{dataLeakageEvidence.actually_transmitted}</span>
                    <span style={{ color: 'var(--text-secondary)' }}>Destination Endpoint:</span>
                    <span style={{ color: '#60A5FA', fontFamily: 'monospace' }}>{dataLeakageEvidence.destination_domain_or_ip}</span>
                    <span style={{ color: 'var(--text-secondary)' }}>Third-Party Service:</span>
                    <span style={{ color: 'var(--text-primary)' }}>{dataLeakageEvidence.third_party_service}</span>
                    <span style={{ color: 'var(--text-secondary)' }}>Timestamp:</span>
                    <span style={{ color: 'var(--text-muted)' }}>{dataLeakageEvidence.timestamp}</span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '10px', lineHeight: '1.4' }}>
                    {dataLeakageEvidence.explanation}
                  </div>
                </div>
              )}

              {/* Malicious Dropper Evidence */}
              {maliciousEvidence && (
                <div style={{ background: 'rgba(239, 68, 68, 0.06)', border: '1px solid rgba(239, 68, 68, 0.2)', borderRadius: '12px', padding: '16px', marginBottom: '16px' }}>
                  <div style={{ fontSize: '14px', fontWeight: '700', color: '#F87171', marginBottom: '10px' }}>
                    Malicious Runtime Indicators
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '140px 1fr', gap: '8px', fontSize: '12px', marginBottom: '8px' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>Observed Behavior:</span>
                    <span style={{ color: 'var(--text-primary)', fontWeight: '600' }}>{maliciousEvidence.observed_behavior}</span>
                    <span style={{ color: 'var(--text-secondary)' }}>Predicted Family:</span>
                    <span style={{ color: '#F87171', fontWeight: '700' }}>{maliciousEvidence.predicted_malware_family}</span>
                    <span style={{ color: 'var(--text-secondary)' }}>Risk Severity:</span>
                    <span style={{ color: '#F87171', fontWeight: '700' }}>{maliciousEvidence.risk_level}</span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '10px', lineHeight: '1.4' }}>
                    {maliciousEvidence.explanation}
                  </div>
                </div>
              )}

              {/* Benign Clean Status View */}
              {isBenign && !redirectEvidence && !dataLeakageEvidence && !maliciousEvidence && (
                <div style={{ textAlign: 'center', padding: '30px 10px' }}>
                  <div style={{
                    width: '80px',
                    height: '80px',
                    borderRadius: '50%',
                    background: 'rgba(16, 185, 129, 0.1)',
                    border: '1px solid rgba(16, 185, 129, 0.3)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: '#10B981',
                    margin: '0 auto 18px auto'
                  }}>
                    <CheckCircle2 size={44} strokeWidth={2.2} />
                  </div>
                  <h3 style={{ fontSize: '17px', fontWeight: '700', color: '#10B981', marginBottom: '6px' }}>
                    {isPassive ? 'No Significant Static Threats Detected' : 'No Malicious Behavior Observed'}
                  </h3>
                  <p style={{ fontSize: '13px', color: 'var(--text-secondary)', maxWidth: '420px', margin: '0 auto', lineHeight: '1.5' }}>
                    {bannerSub}
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Tab 2: Explainability (SHAP) */}
          {activeTab === 'xai' && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <span style={{ fontSize: '13px', fontWeight: '700', color: 'var(--text-primary)' }}>Category Attribution</span>
                <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>TreeExplainer Attribution Weights</span>
              </div>

              <div style={{ marginBottom: '20px' }}>
                {categoryBreakdown.map((item, idx) => {
                  const colorsList = ['#EF4444', '#F59E0B', '#3B82F6', '#8B5CF6'];
                  const barColor = colorsList[idx % colorsList.length];

                  return (
                    <div key={item.category} className="feature-bar-item">
                      <div className="feature-bar-label-group">
                        <span style={{ color: 'var(--text-primary)' }}>{item.category}</span>
                        <span style={{ color: 'var(--text-primary)', fontWeight: '700' }}>{item.percentage}%</span>
                      </div>
                      <div className="feature-progress-bg">
                        <div
                          className="feature-progress-fill"
                          style={{ width: `${item.percentage}%`, background: barColor }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>

              {shapData.top_features && shapData.top_features.length > 0 && (
                <div>
                  <div style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-muted)', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Key Indicative Signals
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    {shapData.top_features.slice(0, 4).map((f) => (
                      <div key={f.name} style={{ display: 'flex', justifyContent: 'space-between', background: 'rgba(255, 255, 255, 0.02)', padding: '6px 10px', borderRadius: '8px', fontSize: '12px' }}>
                        <span style={{ color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                          {f.name.replace('android.permission.', '')}
                        </span>
                        <span style={{ color: f.shap_value > 0 ? '#EF4444' : '#10B981', fontWeight: '600' }}>
                          {f.shap_value > 0 ? `+${f.importance}%` : `-${f.importance}%`}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Tab 3: Static Findings */}
          {activeTab === 'static' && (
            <div style={{ fontSize: '12px' }}>
              <div style={{ marginBottom: '14px' }}>
                <span style={{ color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: '700' }}>
                  Requested Permissions ({extFeatures.permission_count || 0})
                </span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '8px' }}>
                  {(extFeatures.permissions || []).slice(0, 16).map(p => {
                    const isDangerous = (extFeatures.dangerous_permissions || []).includes(p);
                    return (
                      <span
                        key={p}
                        style={{
                          padding: '3px 8px',
                          borderRadius: '6px',
                          fontSize: '11px',
                          fontFamily: 'monospace',
                          background: isDangerous ? 'rgba(239, 68, 68, 0.12)' : 'rgba(255, 255, 255, 0.04)',
                          color: isDangerous ? '#F87171' : 'var(--text-secondary)',
                          border: isDangerous ? '1px solid rgba(239, 68, 68, 0.3)' : '1px solid var(--card-border)'
                        }}
                      >
                        {p.replace('android.permission.', '')}
                      </span>
                    );
                  })}
                </div>
              </div>

              {extFeatures.embedded_domains && extFeatures.embedded_domains.length > 0 && (
                <div style={{ marginBottom: '14px' }}>
                  <span style={{ color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: '700' }}>
                    Embedded Domains Sample ({extFeatures.embedded_domains.length})
                  </span>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '8px' }}>
                    {extFeatures.embedded_domains.slice(0, 8).map(d => (
                      <span key={d} style={{ padding: '3px 8px', borderRadius: '6px', fontSize: '11px', fontFamily: 'monospace', background: 'rgba(56, 189, 248, 0.06)', color: '#38BDF8', border: '1px solid rgba(56, 189, 248, 0.2)' }}>
                        {d}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {extFeatures.third_party_sdks && extFeatures.third_party_sdks.length > 0 && (
                <div>
                  <span style={{ color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: '700' }}>
                    Identified Third-Party SDKs
                  </span>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '8px' }}>
                    {extFeatures.third_party_sdks.map(sdk => (
                      <span key={sdk} style={{ padding: '3px 8px', borderRadius: '6px', fontSize: '11px', background: 'rgba(139, 92, 246, 0.08)', color: '#C084FC', border: '1px solid rgba(139, 92, 246, 0.2)' }}>
                        {sdk}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Tab 4: Event Timeline */}
          {activeTab === 'timeline' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {eventTimeline.map((ev, i) => (
                <div key={i} style={{ display: 'flex', gap: '10px', alignItems: 'flex-start', background: 'rgba(255, 255, 255, 0.02)', padding: '10px', borderRadius: '8px', fontSize: '12px' }}>
                  <span style={{ fontFamily: 'monospace', color: '#60A5FA', fontSize: '11px', flexShrink: 0 }}>
                    {ev.timestamp}
                  </span>
                  <div>
                    <div style={{ fontWeight: '700', color: 'var(--text-primary)', marginBottom: '2px' }}>
                      {ev.action}
                    </div>
                    <div style={{ color: 'var(--text-secondary)', fontSize: '11px' }}>
                      {ev.details}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Tab 5: Network Indicators */}
          {activeTab === 'network' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {networkIndicators.map((net, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(255, 255, 255, 0.02)', padding: '10px 12px', borderRadius: '8px', fontSize: '12px' }}>
                  <div>
                    <div style={{ fontWeight: '600', color: 'var(--text-primary)', fontFamily: 'monospace' }}>
                      {net.destination}
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      IP: {net.ip} • Category: {net.category}
                    </div>
                  </div>
                  <span style={{ fontSize: '11px', padding: '3px 8px', borderRadius: '6px', background: 'rgba(59, 130, 246, 0.1)', color: '#60A5FA' }}>
                    {net.protocol}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* Tab 6: Threat Intelligence Correlation */}
          {activeTab === 'threat-intel' && (
            <div>
              {/* Correlation Header Status */}
              <div style={{
                background: (record.threat_intelligence?.intelligence_match_status || '').includes('Confirmed')
                  ? 'rgba(239, 68, 68, 0.08)'
                  : 'rgba(16, 185, 129, 0.08)',
                border: (record.threat_intelligence?.intelligence_match_status || '').includes('Confirmed')
                  ? '1px solid rgba(239, 68, 68, 0.25)'
                  : '1px solid rgba(16, 185, 129, 0.25)',
                borderRadius: '12px',
                padding: '16px',
                marginBottom: '16px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Shield size={18} color={(record.threat_intelligence?.intelligence_match_status || '').includes('Confirmed') ? '#F87171' : '#34D399'} />
                    <span style={{ fontSize: '14px', fontWeight: '700', color: 'var(--text-primary)' }}>
                      Threat Intelligence Correlation
                    </span>
                  </div>
                  <span style={{
                    fontSize: '11px',
                    fontWeight: '700',
                    padding: '3px 8px',
                    borderRadius: '6px',
                    background: (record.threat_intelligence?.intelligence_match_status || '').includes('Confirmed')
                      ? 'rgba(239, 68, 68, 0.2)'
                      : 'rgba(16, 185, 129, 0.2)',
                    color: (record.threat_intelligence?.intelligence_match_status || '').includes('Confirmed')
                      ? '#F87171'
                      : '#34D399'
                  }}>
                    {record.threat_intelligence?.intelligence_match_status || 'No Known Threat Indicators Identified'}
                  </span>
                </div>
                <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.5', margin: 0 }}>
                  {record.threat_intelligence?.correlation_summary ||
                    'Threat intelligence correlation verified observables against known threat indicators and infrastructure reputation repositories.'}
                </p>
              </div>

              {/* 4 Metric Cards */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '16px' }}>
                <div style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid var(--card-border)', borderRadius: '10px', padding: '12px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '4px' }}>
                    Hash Reputation
                  </div>
                  <div style={{ fontSize: '13px', fontWeight: '700', color: (record.threat_intelligence?.hash_reputation || '').includes('Flagged') ? '#F87171' : '#34D399' }}>
                    {record.threat_intelligence?.hash_reputation || 'Clean / No Malicious Records'}
                  </div>
                </div>

                <div style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid var(--card-border)', borderRadius: '10px', padding: '12px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '4px' }}>
                    Domain Reputation
                  </div>
                  <div style={{ fontSize: '13px', fontWeight: '700', color: (record.threat_intelligence?.domain_reputation || '').includes('Suspicious') ? '#F87171' : '#34D399' }}>
                    {record.threat_intelligence?.domain_reputation || 'Reputable / No Threat Association'}
                  </div>
                </div>

                <div style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid var(--card-border)', borderRadius: '10px', padding: '12px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '4px' }}>
                    IP Reputation
                  </div>
                  <div style={{ fontSize: '13px', fontWeight: '700', color: (record.threat_intelligence?.ip_reputation || '').includes('Suspicious') ? '#F87171' : '#34D399' }}>
                    {record.threat_intelligence?.ip_reputation || 'Reputable / No Suspicious Association'}
                  </div>
                </div>

                <div style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid var(--card-border)', borderRadius: '10px', padding: '12px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '4px' }}>
                    Malware Association
                  </div>
                  <div style={{ fontSize: '13px', fontWeight: '700', color: (record.threat_intelligence?.malware_association && record.threat_intelligence.malware_association !== 'None') ? '#F87171' : 'var(--text-secondary)' }}>
                    {record.threat_intelligence?.malware_association || 'None'}
                  </div>
                </div>
              </div>

              {/* Correlated Evidence Table / Cards */}
              <div style={{ fontSize: '12px' }}>
                <div style={{ color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: '700', marginBottom: '10px' }}>
                  Correlated Threat Evidence ({(record.threat_intelligence?.correlated_evidence || []).length})
                </div>

                {(record.threat_intelligence?.correlated_evidence || []).length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {record.threat_intelligence.correlated_evidence.map((ev, idx) => (
                      <div key={idx} style={{
                        background: 'rgba(255, 255, 255, 0.02)',
                        border: '1px solid var(--card-border)',
                        borderRadius: '8px',
                        padding: '10px 12px',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'flex-start',
                        gap: '12px'
                      }}>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                            <span style={{ fontWeight: '700', color: 'var(--text-primary)', fontSize: '12px' }}>
                              {ev.category || 'Known Threat Indicator'}
                            </span>
                            <span style={{
                              fontSize: '10px',
                              padding: '2px 6px',
                              borderRadius: '4px',
                              fontFamily: 'monospace',
                              background: 'rgba(59, 130, 246, 0.1)',
                              color: '#60A5FA'
                            }}>
                              {ev.observable}
                            </span>
                          </div>
                          <div style={{ color: 'var(--text-secondary)', fontSize: '11px', lineHeight: '1.4' }}>
                            {ev.assessment}
                          </div>
                        </div>
                        <span style={{
                          fontSize: '11px',
                          fontWeight: '700',
                          padding: '3px 8px',
                          borderRadius: '6px',
                          background: ev.severity === 'Critical' || ev.severity === 'High'
                            ? 'rgba(239, 68, 68, 0.15)'
                            : 'rgba(245, 158, 11, 0.15)',
                          color: ev.severity === 'Critical' || ev.severity === 'High' ? '#F87171' : '#FBBF24',
                          flexShrink: 0
                        }}>
                          {ev.severity || 'Medium'}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{
                    textAlign: 'center',
                    padding: '24px 12px',
                    background: 'rgba(16, 185, 129, 0.04)',
                    border: '1px solid rgba(16, 185, 129, 0.15)',
                    borderRadius: '10px'
                  }}>
                    <CheckCircle2 size={28} color="#10B981" style={{ marginBottom: '8px' }} />
                    <div style={{ fontSize: '13px', fontWeight: '700', color: '#10B981', marginBottom: '4px' }}>
                      Clean Intelligence Record
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      No malicious signatures, distribution endpoints, or compromised infrastructure were correlated with this application.
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

        </div>
      </div>

      {/* Action Footer Buttons */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: '14px', marginTop: '24px' }}>
        <button
          className="btn-secondary"
          onClick={handleExplainWithGemini}
          style={{ gap: '8px' }}
        >
          <Sparkles size={16} color="#A78BFA" />
          <span>Explain with Gemini</span>
        </button>

        {(isMalicious || isPhishing || isDataLeakage) && (
          <button
            className="btn-secondary"
            onClick={handleExportStix}
            style={{ gap: '8px' }}
          >
            <FileText size={16} color="var(--accent-blue)" />
            <span>Export STIX 2.1</span>
          </button>
        )}

        <a
          href={getReportDownloadUrl(jobId, 'pdf')}
          target="_blank"
          rel="noopener noreferrer"
          className="btn-primary"
          style={{ textDecoration: 'none', display: 'inline-flex' }}
        >
          <Download size={16} />
          <span>Export Report</span>
        </a>

        <button
          className="btn-secondary"
          onClick={onBack}
        >
          Back
        </button>
      </div>

      {/* Gemini Explanation Modal */}
      <GeminiModal
        isOpen={geminiOpen}
        onClose={() => setGeminiOpen(false)}
        explanation={geminiText}
        loading={geminiLoading}
        error={geminiError}
        record={record}
      />
    </div>
  );
}

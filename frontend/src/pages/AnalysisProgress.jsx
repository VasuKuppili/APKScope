import React, { useEffect, useState } from 'react';
import { ArrowLeft, Cpu, FileSearch, Clock, ShieldAlert, Sparkles, CheckCircle2 } from 'lucide-react';
import CircularProgress from '../components/CircularProgress';
import { getJobStatus, cancelJob } from '../services/api';

export default function AnalysisProgress({ jobInfo, onComplete, onBack }) {
  const [job, setJob] = useState({
    status: 'ANALYZING',
    progress: 10,
    status_message: 'Initializing analysis engine...'
  });
  const [cancelling, setCancelling] = useState(false);
  const [secondsElapsed, setSecondsElapsed] = useState(0);

  const isActiveMode = jobInfo?.mode === 'active';
  const modeLabel = isActiveMode ? 'Active Sandbox Analysis' : 'Passive Static Analysis';

  // Elapsed runtime counter
  useEffect(() => {
    const timer = setInterval(() => {
      setSecondsElapsed(prev => prev + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Poll job status
  useEffect(() => {
    if (!jobInfo?.jobId) return;

    let isSubscribed = true;
    const interval = setInterval(async () => {
      try {
        const data = await getJobStatus(jobInfo.jobId);
        if (!isSubscribed) return;

        setJob(data);

        if (data.status === 'COMPLETED') {
          clearInterval(interval);
          setTimeout(() => onComplete(jobInfo.jobId), 700);
        } else if (data.status === 'FAILED' || data.status === 'CANCELLED') {
          clearInterval(interval);
        }
      } catch (err) {
        // Continue polling until job is accessible
      }
    }, 600);

    return () => {
      isSubscribed = false;
      clearInterval(interval);
    };
  }, [jobInfo?.jobId, onComplete]);

  const handleCancel = async () => {
    if (!jobInfo?.jobId) return;
    setCancelling(true);
    try {
      await cancelJob(jobInfo.jobId);
      onBack();
    } catch (err) {
      setCancelling(false);
    }
  };

  const formatTime = (secs) => {
    const m = Math.floor(secs / 60).toString().padStart(2, '0');
    const s = (secs % 60).toString().padStart(2, '0');
    return `${m}:${s}`;
  };

  // Staged phase breadcrumbs
  const activeStages = [
    { label: 'VM Boot', min: 0, max: 25 },
    { label: 'Install APK', min: 26, max: 48 },
    { label: 'Touch Monkey Events', min: 49, max: 68 },
    { label: 'Telemetry Monitoring', min: 69, max: 88 },
    { label: 'AI Classification', min: 89, max: 100 }
  ];

  const passiveStages = [
    { label: 'Archive Check', min: 0, max: 25 },
    { label: 'Manifest & Perms', min: 26, max: 50 },
    { label: 'DEX Disassembly', min: 51, max: 75 },
    { label: 'AI Static Signatures', min: 76, max: 100 }
  ];

  const stages = isActiveMode ? activeStages : passiveStages;
  const currentProgress = job.progress || 10;

  return (
    <div>
      {/* Top Navigation */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '28px' }}>
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
          <span style={{ color: '#FFFFFF' }}>{modeLabel}</span>
        </button>

        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: '8px', 
          background: 'rgba(255, 255, 255, 0.04)', 
          border: '1px solid var(--card-border)', 
          borderRadius: '20px', 
          padding: '6px 14px',
          fontSize: '13px',
          color: 'var(--text-secondary)'
        }}>
          <Clock size={14} color="var(--accent-blue)" />
          <span>Elapsed: <strong style={{ color: '#FFFFFF' }}>{formatTime(secondsElapsed)}</strong></span>
        </div>
      </div>

      {/* Main Analysis Progress Card */}
      <div 
        className="glass-card" 
        style={{ 
          maxWidth: '740px', 
          margin: '0 auto', 
          padding: '50px 36px', 
          textAlign: 'center',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center'
        }}
      >
        {/* Animated Circular Gauge */}
        <div style={{ position: 'relative', marginBottom: '32px' }}>
          <CircularProgress percentage={currentProgress} size={210} strokeWidth={16} />
          <div style={{
            position: 'absolute',
            inset: '-12px',
            borderRadius: '50%',
            border: '1px dashed rgba(59, 130, 246, 0.25)',
            pointerEvents: 'none',
            animation: 'spin 20s linear infinite'
          }} />
        </div>

        {/* Status Headings */}
        <h2 style={{ fontSize: '22px', fontWeight: '800', color: '#FFFFFF', marginBottom: '10px' }}>
          {job.status === 'FAILED' ? 'Analysis Failed' : (isActiveMode ? 'Executing Sandbox Emulation...' : 'Inspecting APK Structures...')}
        </h2>
        
        <p style={{ 
          fontSize: '14px', 
          color: 'var(--text-secondary)', 
          maxWidth: '480px', 
          lineHeight: '1.5', 
          marginBottom: '28px',
          minHeight: '42px'
        }}>
          {job.status_message || 'Analyzing application features and comparing with malware intelligence models...'}
        </p>

        {/* Live Staged Progress Breadcrumbs */}
        <div style={{ 
          display: 'flex', 
          flexWrap: 'wrap', 
          justifyContent: 'center', 
          gap: '8px', 
          marginBottom: '36px',
          maxWidth: '620px'
        }}>
          {stages.map((stage, idx) => {
            const isCompleted = currentProgress > stage.max;
            const isCurrent = currentProgress >= stage.min && currentProgress <= stage.max;

            return (
              <div 
                key={stage.label}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '6px 12px',
                  borderRadius: '16px',
                  fontSize: '12px',
                  fontWeight: isCurrent ? '700' : '500',
                  background: isCurrent 
                    ? 'rgba(59, 130, 246, 0.18)' 
                    : isCompleted 
                      ? 'rgba(16, 185, 129, 0.1)' 
                      : 'rgba(255, 255, 255, 0.03)',
                  border: isCurrent 
                    ? '1px solid var(--accent-blue)' 
                    : isCompleted 
                      ? '1px solid rgba(16, 185, 129, 0.3)' 
                      : '1px solid var(--card-border)',
                  color: isCurrent 
                    ? '#60A5FA' 
                    : isCompleted 
                      ? '#34D399' 
                      : 'var(--text-muted)',
                  boxShadow: isCurrent ? '0 0 12px rgba(59, 130, 246, 0.25)' : 'none',
                  transition: 'all 0.3s ease'
                }}
              >
                {isCompleted ? <CheckCircle2 size={13} color="#10B981" /> : <span>{idx + 1}.</span>}
                <span>{stage.label}</span>
              </div>
            );
          })}
        </div>

        {/* Cancel Button */}
        <button
          className="btn-secondary"
          onClick={handleCancel}
          disabled={cancelling || job.status === 'COMPLETED'}
          style={{ minWidth: '140px', justifyContent: 'center' }}
        >
          {cancelling ? 'Cancelling...' : 'Cancel Scan'}
        </button>
      </div>
    </div>
  );
}

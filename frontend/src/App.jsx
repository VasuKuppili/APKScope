import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import UploadModal from './components/UploadModal';
import Home from './pages/Home';
import AnalysisProgress from './pages/AnalysisProgress';
import Results from './pages/Results';
import History from './pages/History';
import ThreatIntelligence from './pages/ThreatIntelligence';
import Settings from './pages/Settings';
import About from './pages/About';
import { checkHealth } from './services/api';

export default function App() {
  const [activePage, setActivePage] = useState('home');
  const [isReady, setIsReady] = useState(true);

  // Upload modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [analysisMode, setAnalysisMode] = useState('passive');

  // Job and result tracking
  const [activeJob, setActiveJob] = useState(null);
  const [resultJobId, setResultJobId] = useState(null);

  // Initialize theme from storage
  useEffect(() => {
    const savedTheme = localStorage.getItem('app_theme') || 'dark';
    if (savedTheme === 'system') {
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      document.documentElement.setAttribute('data-theme', prefersDark ? 'dark' : 'light');
    } else {
      document.documentElement.setAttribute('data-theme', savedTheme);
    }
  }, []);

  // Periodic health check
  useEffect(() => {
    checkHealth()
      .then(res => setIsReady(res.status === 'online'))
      .catch(() => setIsReady(false));

    const interval = setInterval(() => {
      checkHealth()
        .then(res => setIsReady(res.status === 'online'))
        .catch(() => setIsReady(false));
    }, 15000);

    return () => clearInterval(interval);
  }, []);

  const handleStartAnalysis = (mode) => {
    setAnalysisMode(mode);
    setModalOpen(true);
  };

  const handleNav = (page) => {
    setModalOpen(false);
    if (page === 'analysis') {
      setTimeout(() => {
        handleStartAnalysis('passive');
      }, 20);
    } else {
      setActivePage(page);
    }
  };

  const handleJobStarted = (jobData) => {
    setModalOpen(false);
    setActiveJob(jobData);
    setActivePage('progress');
  };

  const handleJobComplete = (jobId) => {
    setResultJobId(jobId);
    setActivePage('results');
  };

  const handleSelectHistoryJob = (jobId) => {
    setResultJobId(jobId);
    setActivePage('results');
  };

  return (
    <div className="app-layout">
      {/* Sidebar matching UI Reference */}
      <Sidebar 
        activePage={activePage} 
        setActivePage={handleNav} 
        isReady={isReady} 
      />

      {/* Main Content Area */}
      <main className="main-content">
        {activePage === 'home' && (
          <Home onStartAnalysis={handleStartAnalysis} />
        )}

        {activePage === 'progress' && (
          <AnalysisProgress 
            jobInfo={activeJob} 
            onComplete={handleJobComplete}
            onBack={() => setActivePage('home')}
          />
        )}

        {activePage === 'results' && (
          <Results 
            jobId={resultJobId} 
            onBack={() => setActivePage('home')} 
          />
        )}

        {activePage === 'history' && (
          <History onSelectJob={handleSelectHistoryJob} />
        )}

        {activePage === 'threat-intel' && (
          <ThreatIntelligence />
        )}

        {activePage === 'settings' && (
          <Settings />
        )}

        {activePage === 'about' && (
          <About />
        )}
      </main>

      {/* Upload & Validation Modal */}
      <UploadModal 
        isOpen={modalOpen} 
        onClose={() => setModalOpen(false)} 
        mode={analysisMode}
        onJobStarted={handleJobStarted}
      />
    </div>
  );
}

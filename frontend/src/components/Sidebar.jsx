import React from 'react';
import { 
  ShieldAlert, 
  Home, 
  Search, 
  History, 
  Cpu, 
  Settings, 
  Info 
} from 'lucide-react';

export default function Sidebar({ activePage, setActivePage, isReady = true }) {
  const navItems = [
    { id: 'home', label: 'Home', icon: Home },
    { id: 'analysis', label: 'Analysis', icon: Search },
    { id: 'history', label: 'History', icon: History },
    { id: 'threat-intel', label: 'Threat Intel', icon: Cpu },
    { id: 'settings', label: 'Settings', icon: Settings },
    { id: 'about', label: 'About', icon: Info },
  ];

  return (
    <aside className="sidebar">
      <div>
        <div className="sidebar-logo">
          <div className="logo-icon-wrapper">
            <ShieldAlert size={26} strokeWidth={2.2} />
          </div>
          <div>
            <div className="logo-text-title">Malware</div>
            <div className="logo-text-sub">Classifier</div>
          </div>
        </div>

        <nav className="sidebar-nav">
          {navItems.map((item) => {
            const IconComponent = item.icon;
            const isActive = activePage === item.id || 
              (item.id === 'analysis' && (activePage === 'progress' || activePage === 'results'));

            return (
              <button
                key={item.id}
                className={`nav-item ${isActive ? 'active' : ''}`}
                onClick={() => setActivePage(item.id)}
              >
                <IconComponent size={19} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      <div className="sidebar-status">
        <span 
          className="status-dot" 
          style={{ 
            backgroundColor: isReady ? '#10B981' : '#F59E0B', 
            boxShadow: `0 0 8px ${isReady ? '#10B981' : '#F59E0B'}` 
          }} 
        />
        <span className="status-text">{isReady ? 'Ready' : 'Checking API...'}</span>
      </div>
    </aside>
  );
}

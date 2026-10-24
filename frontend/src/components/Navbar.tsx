import React, { useState } from 'react';
import {
  Shield,
  Activity,
  Terminal,
  History,
  BookOpen,
  Fingerprint,
  Settings,
  Users,
  LogOut,
  Menu,
  X,
  Server,
  Cpu,
} from 'lucide-react';
import { HealthCheckResult } from '../api/client';
import { useAuth } from '../context/AuthContext';

export type SOCTab = 'overview' | 'workbench' | 'history' | 'policies' | 'audit' | 'settings' | 'users';

interface NavbarProps {
  activeTab: SOCTab;
  onTabChange: (tab: SOCTab) => void;
  health: HealthCheckResult | null;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, onTabChange, health }) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const { user, logout, canScan, canViewAudit, canManageUsers } = useAuth();
  const isOnline = health?.data?.status === 'healthy';
  const isLLMConfigured = health?.data?.environment?.llm_configured ?? false;

  const navItems: { id: SOCTab; label: string; icon: React.ReactNode; hidden?: boolean }[] = [
    { id: 'overview', label: 'Overview', icon: <Activity size={16} strokeWidth={1.8} /> },
    { id: 'workbench', label: 'Scan Workbench', icon: <Terminal size={16} strokeWidth={1.8} />, hidden: !canScan },
    { id: 'history', label: 'Scan History', icon: <History size={16} strokeWidth={1.8} /> },
    { id: 'policies', label: 'Policy Explorer', icon: <BookOpen size={16} strokeWidth={1.8} /> },
    { id: 'audit', label: 'Audit Trail', icon: <Fingerprint size={16} strokeWidth={1.8} />, hidden: !canViewAudit },
    { id: 'users', label: 'Identity & RBAC', icon: <Users size={16} strokeWidth={1.8} />, hidden: !canManageUsers },
    { id: 'settings', label: 'Settings & Health', icon: <Settings size={16} strokeWidth={1.8} /> },
  ];

  const visibleNavItems = navItems.filter((i) => !i.hidden);

  const handleNavClick = (id: SOCTab) => {
    onTabChange(id);
    setMobileMenuOpen(false);
  };

  return (
    <>
      {/* Mobile Top Bar */}
      <div
        className="mobile-header"
        style={{
          display: 'none',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '12px 18px',
          background: 'var(--bg-surface)',
          borderBottom: '1px solid var(--border-primary)',
          position: 'sticky',
          top: 0,
          zIndex: 90,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div
            style={{
              width: '28px',
              height: '28px',
              borderRadius: 'var(--radius-sm)',
              background: '#151515',
              border: '1px solid var(--border-strong)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Shield size={16} color="#ffffff" strokeWidth={2} />
          </div>
          <span style={{ fontWeight: 700, fontSize: '0.95rem', letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
            DataShield AI
          </span>
        </div>
        <button
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          aria-label="Toggle navigation menu"
          style={{
            background: 'transparent',
            border: 'none',
            color: 'var(--text-primary)',
            padding: '6px',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
          }}
        >
          {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </div>

      {/* Desktop Sidebar / Mobile Collapsible Drawer */}
      <aside
        className={`soc-sidebar ${mobileMenuOpen ? 'mobile-open' : ''}`}
        style={{
          width: '240px',
          background: 'var(--bg-surface)',
          borderRight: '1px solid var(--border-primary)',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          height: '100vh',
          position: 'sticky',
          top: 0,
          zIndex: 80,
          flexShrink: 0,
        }}
      >
        {/* Top: Wordmark & Navigation */}
        <div>
          {/* Brand Header */}
          <div
            style={{
              padding: '24px 20px',
              borderBottom: '1px solid var(--border-subtle)',
              cursor: 'pointer',
            }}
            onClick={() => handleNavClick('overview')}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div
                style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: 'var(--radius-sm)',
                  background: '#181818',
                  border: '1px solid var(--border-strong)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <Shield size={18} color="#ffffff" strokeWidth={2} />
              </div>
              <div>
                <div
                  style={{
                    fontWeight: 700,
                    fontSize: '0.98rem',
                    letterSpacing: '-0.02em',
                    color: 'var(--text-primary)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                  }}
                >
                  <span>DataShield</span>
                  <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)' }}>AI</span>
                </div>
                <div
                  style={{
                    fontSize: '0.66rem',
                    color: 'var(--text-muted)',
                    textTransform: 'uppercase',
                    letterSpacing: '0.08em',
                    fontWeight: 600,
                  }}
                >
                  Enterprise SOC
                </div>
              </div>
            </div>
          </div>

          {/* Section Label */}
          <div
            style={{
              padding: '16px 20px 8px',
              fontSize: '0.68rem',
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              fontWeight: 600,
            }}
          >
            Navigation
          </div>

          {/* Nav Items List */}
          <nav style={{ display: 'flex', flexDirection: 'column', gap: '2px', padding: '0 10px' }}>
            {visibleNavItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  id={`nav-item-${item.id}`}
                  onClick={() => handleNavClick(item.id)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px',
                    padding: '8px 12px',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: '0.83rem',
                    fontWeight: isActive ? 600 : 500,
                    color: isActive ? '#f5f5f5' : 'var(--text-secondary)',
                    background: isActive ? 'var(--bg-hover)' : 'transparent',
                    borderLeft: isActive ? '2px solid #f5f5f5' : '2px solid transparent',
                    borderTop: 'none',
                    borderRight: 'none',
                    borderBottom: 'none',
                    cursor: 'pointer',
                    width: '100%',
                    textAlign: 'left',
                    transition: 'all 120ms ease',
                  }}
                >
                  <span style={{ color: isActive ? '#f5f5f5' : 'var(--text-muted)', display: 'flex' }}>
                    {item.icon}
                  </span>
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Bottom Section: Authenticated User & Telemetry */}
        <div
          style={{
            padding: '16px 16px 20px',
            borderTop: '1px solid var(--border-subtle)',
            display: 'flex',
            flexDirection: 'column',
            gap: '10px',
          }}
        >
          {/* User Identity Card */}
          {user && (
            <div
              style={{
                padding: '8px 10px',
                borderRadius: 'var(--radius-sm)',
                background: '#161616',
                border: '1px solid var(--border-strong)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '4px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                <div
                  style={{
                    width: '26px',
                    height: '26px',
                    borderRadius: '50%',
                    background: '#242424',
                    border: '1px solid var(--border-subtle)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '0.7rem',
                    fontWeight: 700,
                    color: 'var(--text-secondary)',
                    flexShrink: 0,
                  }}
                >
                  {user.username.substring(0, 2).toUpperCase()}
                </div>
                <div style={{ minWidth: 0, overflow: 'hidden' }}>
                  <div
                    style={{
                      fontWeight: 600,
                      fontSize: '0.78rem',
                      color: 'var(--text-primary)',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }}
                  >
                    {user.username}
                  </div>
                  <div
                    style={{
                      fontSize: '0.64rem',
                      color:
                        user.role === 'admin'
                          ? '#f87171'
                          : user.role === 'analyst'
                          ? '#60a5fa'
                          : '#9ca3af',
                      fontWeight: 700,
                      letterSpacing: '0.04em',
                      textTransform: 'uppercase',
                    }}
                  >
                    {user.role}
                  </div>
                </div>
              </div>

              <button
                id="btn-sign-out"
                onClick={() => logout()}
                title="Sign Out"
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  padding: '4px',
                  display: 'flex',
                  alignItems: 'center',
                  borderRadius: 'var(--radius-xs)',
                  transition: 'color 120ms ease',
                }}
                onMouseEnter={(e) => (e.currentTarget.style.color = '#ef4444')}
                onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-muted)')}
              >
                <LogOut size={15} />
              </button>
            </div>
          )}

          <div
            style={{
              fontSize: '0.66rem',
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              fontWeight: 600,
            }}
          >
            Telemetry
          </div>

          {/* API Gateway Status */}
          <div
            title={isOnline ? 'FastAPI Gateway Bound to 127.0.0.1:8001' : 'Backend Unreachable'}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '7px 10px',
              borderRadius: 'var(--radius-sm)',
              background: '#141414',
              border: '1px solid var(--border-subtle)',
              fontSize: '0.74rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '7px', color: 'var(--text-secondary)' }}>
              <Server size={13} color="var(--text-muted)" strokeWidth={1.8} />
              <span>Gateway</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span className={isOnline ? 'beacon-dot-live' : 'beacon-dot-offline'} />
              <span
                className="font-mono"
                style={{
                  fontSize: '0.72rem',
                  fontWeight: 600,
                  color: isOnline ? '#f5f5f5' : 'var(--text-muted)',
                }}
              >
                {isOnline ? '8001' : 'Down'}
              </span>
            </div>
          </div>

          {/* Gemini AI Status */}
          <div
            title={isLLMConfigured ? 'Gemini 2.5 Active (Advisory Analysis)' : 'Deterministic Fallback Active'}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '7px 10px',
              borderRadius: 'var(--radius-sm)',
              background: '#141414',
              border: '1px solid var(--border-subtle)',
              fontSize: '0.74rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '7px', color: 'var(--text-secondary)' }}>
              <Cpu size={13} color="var(--text-muted)" strokeWidth={1.8} />
              <span>AI Engine</span>
            </div>
            <span
              style={{
                fontSize: '0.7rem',
                fontWeight: 600,
                color: isLLMConfigured ? '#f5f5f5' : 'var(--text-muted)',
                padding: '2px 6px',
                borderRadius: 'var(--radius-xs)',
                background: isLLMConfigured ? '#222222' : 'transparent',
                border: isLLMConfigured ? '1px solid #383838' : '1px solid var(--border-subtle)',
              }}
            >
              {isLLMConfigured ? 'Gemini 2.5' : 'Fallback'}
            </span>
          </div>
        </div>
      </aside>

      {/* Style overrides for responsive sidebar */}
      <style>{`
        @media (max-width: 899px) {
          .mobile-header {
            display: flex !important;
          }
          .soc-sidebar {
            position: fixed !important;
            left: 0;
            top: 53px;
            height: calc(100vh - 53px) !important;
            transform: translateX(-100%);
            transition: transform 200ms ease;
            z-index: 100 !important;
          }
          .soc-sidebar.mobile-open {
            transform: translateX(0);
          }
        }
      `}</style>
    </>
  );
};

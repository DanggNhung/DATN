import React, { useState, useRef, useEffect } from 'react';
import {
  Shield,
  History,
  Terminal,
  Users,
  LogIn,
  LogOut,
  Zap,
  Bug,
  ChevronDown,
  Layers,
  Check,
  Menu,
  X
} from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab, user, onOpenAuth, onLogout }) {
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const dropdownRef = useRef(null);

  // Đóng dropdown khi nhấn chuột ra ngoài
  useEffect(() => {
    function handleClickOutside(event) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setDropdownOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const featureItems = [
    {
      id: 'scanner',
      title: 'Quét Mã Tĩnh (SCA)',
      desc: 'Phân tích mã nguồn, phụ thuộc & CISA KEV',
      icon: <Shield size={17} color="#db2777" />
    },
    {
      id: 'dast',
      title: 'Kiểm Thử Động (DAST)',
      desc: 'Mô phỏng tấn công REST API OWASP ZAP',
      icon: <Zap size={17} color="#e11d48" />
    },
    {
      id: 'exploitdb',
      title: 'Thành Phần & Exploit-DB',
      desc: 'Phân tích công nghệ & đối chiếu mã khai thác',
      icon: <Bug size={17} color="#f97316" />
    },
    {
      id: 'extension',
      title: 'VS Code Plugin',
      desc: 'Tích hợp SecShield vào Visual Studio Code',
      icon: <Terminal size={17} color="#06b6d4" />
    }
  ];

  const currentFeature = featureItems.find((item) => item.id === activeTab);
  const isFeatureActive = !!currentFeature;

  return (
    <>
      {/* Pandora Style Top Announcement Banner */}
      <div className="announcement-bar">
        <span>SECSHIELD DEVSECOPS INTELLIGENCE</span>
        <span>•</span>
        <span>KIỂM ĐỊNH BẢO MẬT CHUỖI CUNG ỨNG & DAST THEO CHUẨN OWASP</span>
        <span>•</span>
        <span style={{ textDecoration: 'underline', cursor: 'pointer' }} onClick={() => setActiveTab('exploitdb')}>
          KHÁM PHÁ EXPLOIT-DB NGAY!
        </span>
      </div>

      <header style={{
        borderBottom: '1px solid #fce7f3',
        background: 'rgba(255, 255, 255, 0.96)',
        backdropFilter: 'blur(16px)',
        position: 'sticky',
        top: 0,
        zIndex: 100,
        boxShadow: '0 2px 10px rgba(236, 72, 153, 0.05)'
      }}>
        <div style={{
          maxWidth: 1200,
          margin: '0 auto',
          padding: '12px 20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 16
        }}>
          {/* Brand Logo - In đậm, xóa icon đằng trước */}
          <div 
            onClick={() => setActiveTab('scanner')}
            style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', flexShrink: 0 }}
          >
            <div style={{ 
              fontSize: 20, 
              fontWeight: 800, 
              letterSpacing: '0.04em', 
              textTransform: 'uppercase',
              fontFamily: 'var(--font-heading)',
              color: '#111827',
              display: 'flex', 
              alignItems: 'center', 
              gap: 8 
            }}>
              <span>SECSHIELD</span>
              <span className="brand-subtitle" style={{ 
                fontSize: 10, 
                fontWeight: 600,
                background: '#fdf2f8', 
                color: '#db2777', 
                padding: '2px 8px', 
                borderRadius: 20, 
                border: '1px solid #fbcfe8',
                letterSpacing: '0.03em'
              }}>
                SCA • DAST • EXPLOIT-DB
              </span>
            </div>
          </div>

          {/* Navigation - Desktop */}
          <nav className="desktop-nav">
            {/* Dropdown danh sách tính năng */}
            <div style={{ position: 'relative' }} ref={dropdownRef}>
              <button
                type="button"
                onClick={() => setDropdownOpen(!dropdownOpen)}
                style={{
                  background: isFeatureActive ? '#fdf2f8' : '#ffffff',
                  color: isFeatureActive ? '#db2777' : '#334155',
                  border: isFeatureActive ? '1px solid #f472b6' : '1px solid #fce7f3',
                  padding: '8px 14px',
                  borderRadius: 8,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  fontSize: 13,
                  fontFamily: 'var(--font-heading)',
                  fontWeight: isFeatureActive ? 700 : 600,
                  letterSpacing: '0.02em',
                  transition: 'all 0.2s',
                  boxShadow: isFeatureActive ? '0 2px 8px rgba(236, 72, 153, 0.1)' : '0 1px 3px rgba(0,0,0,0.02)'
                }}
              >
                <Layers size={16} color={isFeatureActive ? '#db2777' : '#64748b'} />
                <span>{currentFeature ? currentFeature.title : 'Danh Sách Tính Năng'}</span>
                <ChevronDown
                  size={14}
                  style={{
                    transform: dropdownOpen ? 'rotate(180deg)' : 'none',
                    transition: 'transform 0.2s'
                  }}
                />
              </button>

              {dropdownOpen && (
                <div style={{
                  position: 'absolute',
                  top: 'calc(100% + 8px)',
                  left: 0,
                  background: '#ffffff',
                  border: '1px solid #fce7f3',
                  borderRadius: 12,
                  boxShadow: '0 12px 30px rgba(236, 72, 153, 0.15), 0 4px 12px rgba(0,0,0,0.04)',
                  padding: 8,
                  minWidth: 320,
                  zIndex: 1000,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 4
                }}>
                  <div style={{
                    padding: '6px 10px',
                    fontSize: 11,
                    fontWeight: 700,
                    color: '#94a3b8',
                    textTransform: 'uppercase',
                    letterSpacing: '0.04em'
                  }}>
                    Danh sách các tính năng
                  </div>

                  {featureItems.map((item) => {
                    const isActive = activeTab === item.id;
                    return (
                      <button
                        key={item.id}
                        type="button"
                        onClick={() => {
                          setActiveTab(item.id);
                          setDropdownOpen(false);
                        }}
                        className={`nav-dropdown-item ${isActive ? 'active' : ''}`}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                          <div style={{
                            width: 32,
                            height: 32,
                            borderRadius: 8,
                            background: isActive ? '#ffe4e6' : '#fdf2f8',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            flexShrink: 0
                          }}>
                            {item.icon}
                          </div>
                          <div>
                            <div style={{
                              fontSize: 13,
                              fontWeight: isActive ? 700 : 600,
                              color: isActive ? '#db2777' : '#111827'
                            }}>
                              {item.title}
                            </div>
                            <div style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>
                              {item.desc}
                            </div>
                          </div>
                        </div>
                        {isActive && <Check size={16} color="#db2777" style={{ flexShrink: 0 }} />}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Lịch Sử Quét */}
            <button
              onClick={() => setActiveTab('history')}
              style={{
                background: activeTab === 'history' ? '#fdf2f8' : 'transparent',
                color: activeTab === 'history' ? '#db2777' : '#475569',
                border: activeTab === 'history' ? '1px solid #f472b6' : '1px solid transparent',
                padding: '8px 14px',
                borderRadius: 8,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 7,
                fontSize: 13,
                fontFamily: 'var(--font-heading)',
                fontWeight: activeTab === 'history' ? 700 : 600,
                letterSpacing: '0.02em',
                transition: 'all 0.2s'
              }}
            >
              <History size={15} />
              <span>Lịch Sử Quét</span>
            </button>

            {/* Admin Tab - Chỉ dành cho quyền admin */}
            {user && user.role === 'admin' && (
              <button
                onClick={() => setActiveTab('admin')}
                style={{
                  background: activeTab === 'admin' ? '#faf5ff' : 'transparent',
                  color: activeTab === 'admin' ? '#9333ea' : '#475569',
                  border: activeTab === 'admin' ? '1px solid #d8b4fe' : '1px solid transparent',
                  padding: '8px 14px',
                  borderRadius: 8,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 7,
                  fontSize: 13,
                  fontFamily: 'var(--font-heading)',
                  fontWeight: 700,
                  letterSpacing: '0.02em',
                  transition: 'all 0.2s'
                }}
              >
                <Users size={15} />
                <span>Quản Trị Admin</span>
              </button>
            )}
          </nav>

          {/* User Account Section - Desktop */}
          <div className="desktop-user-section">
            {user ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                {/* Khung chứa user và lập trình viên viết liền 1 dòng */}
                <div style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: '6px 14px',
                  borderRadius: 8,
                  background: '#ffffff',
                  border: '1px solid #fbcfe8',
                  boxShadow: '0 2px 6px rgba(236, 72, 153, 0.06)',
                  fontSize: 13,
                  lineHeight: 1
                }}>
                  <span style={{ fontWeight: 800, color: '#111827' }}>{user.username}</span>
                  <span style={{ color: '#cbd5e1', fontSize: 12 }}>•</span>
                  <span style={{ 
                    fontSize: 11, 
                    color: user.role === 'admin' ? '#9333ea' : '#db2777', 
                    textTransform: 'uppercase', 
                    fontWeight: 700,
                    letterSpacing: '0.03em'
                  }}>
                    {user.role === 'admin' ? '⚡ Quản trị viên' : 'Lập trình viên'}
                  </span>
                </div>

                <button
                  onClick={onLogout}
                  className="btn-secondary"
                  style={{ padding: '7px 12px', fontSize: 12 }}
                  title="Đăng xuất"
                >
                  <LogOut size={14} />
                  <span>Thoát</span>
                </button>
              </div>
            ) : (
              <button
                onClick={onOpenAuth}
                className="btn-primary"
                style={{ padding: '8px 16px', fontSize: 13 }}
              >
                <LogIn size={15} />
                <span>Đăng Nhập / Đăng Ký</span>
              </button>
            )}
          </div>

          {/* Mobile Menu Toggle Button */}
          <button
            type="button"
            className="mobile-menu-btn"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>

        {/* Mobile Navigation Drawer */}
        {mobileMenuOpen && (
          <div className="mobile-nav-drawer">
            {/* User status on mobile */}
            {user ? (
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '8px 12px',
                borderRadius: 8,
                background: '#fdf2f8',
                border: '1px solid #fbcfe8',
                marginBottom: 8
              }}>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 800, color: '#111827' }}>{user.username}</div>
                  <div style={{ fontSize: 11, color: user.role === 'admin' ? '#9333ea' : '#db2777', fontWeight: 600 }}>
                    {user.role === 'admin' ? '⚡ Quản trị viên' : 'Lập trình viên'}
                  </div>
                </div>
                <button
                  onClick={() => {
                    onLogout();
                    setMobileMenuOpen(false);
                  }}
                  className="btn-secondary"
                  style={{ padding: '5px 10px', fontSize: 12 }}
                >
                  <LogOut size={13} />
                  <span>Thoát</span>
                </button>
              </div>
            ) : (
              <button
                onClick={() => {
                  onOpenAuth();
                  setMobileMenuOpen(false);
                }}
                className="btn-primary"
                style={{ width: '100%', justifyContent: 'center', marginBottom: 10, padding: '10px' }}
              >
                <LogIn size={15} />
                <span>Đăng Nhập / Đăng Ký</span>
              </button>
            )}

            <div style={{ fontSize: 11, fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', padding: '4px 6px', letterSpacing: '0.04em' }}>
              Tính năng bảo mật
            </div>

            {featureItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => {
                    setActiveTab(item.id);
                    setMobileMenuOpen(false);
                  }}
                  className={`mobile-nav-item ${isActive ? 'active' : ''}`}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    {item.icon}
                    <span>{item.title}</span>
                  </div>
                  {isActive && <Check size={15} color="#db2777" style={{ marginLeft: 'auto' }} />}
                </button>
              );
            })}

            <div style={{ height: 1, background: '#fce7f3', margin: '6px 0' }} />

            <button
              type="button"
              onClick={() => {
                setActiveTab('history');
                setMobileMenuOpen(false);
              }}
              className={`mobile-nav-item ${activeTab === 'history' ? 'active' : ''}`}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <History size={16} />
                <span>Lịch Sử Quét</span>
              </div>
              {activeTab === 'history' && <Check size={15} color="#db2777" style={{ marginLeft: 'auto' }} />}
            </button>

            {user && user.role === 'admin' && (
              <button
                type="button"
                onClick={() => {
                  setActiveTab('admin');
                  setMobileMenuOpen(false);
                }}
                className={`mobile-nav-item ${activeTab === 'admin' ? 'active' : ''}`}
                style={{ color: '#9333ea' }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <Users size={16} />
                  <span>Quản Trị Admin</span>
                </div>
                {activeTab === 'admin' && <Check size={15} color="#9333ea" style={{ marginLeft: 'auto' }} />}
              </button>
            )}
          </div>
        )}
      </header>
    </>
  );
}

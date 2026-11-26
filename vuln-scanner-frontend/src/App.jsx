import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Scanner from './components/Scanner';
import ScanResultView from './components/ScanResultView';
import HistoryView from './components/HistoryView';
import ExtensionView from './components/ExtensionView';
import AdminView from './components/AdminView';
import DastScanner from './components/DastScanner';
import ExploitDbView from './components/ExploitDbView';
import AuthModal from './components/AuthModal';
import { authAPI, scanAPI } from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [user, setUser] = useState(null);
  const [currentScan, setCurrentScan] = useState(null);
  const [pendingScan, setPendingScan] = useState(null);
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [publicStats, setPublicStats] = useState(null);

  // Khởi tạo: kiểm tra token và nạp thông tin user
  useEffect(() => {
    const savedUser = localStorage.getItem('user');
    const token = localStorage.getItem('token');
    if (savedUser && token) {
      try {
        setUser(JSON.parse(savedUser));
        // Xác thực lại với server
        authAPI.getMe()
          .then((res) => setUser(res.data.user))
          .catch(() => {
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            setUser(null);
          });
      } catch (e) {
        // Ignored
      }
    }

    // Nạp thống kê công khai
    scanAPI.getPublicStats()
      .then((res) => setPublicStats(res.data.stats))
      .catch((err) => console.error('Lỗi nạp thống kê:', err));
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
    if (activeTab === 'admin') {
      setActiveTab('scanner');
    }
  };

  const handleScanSuccess = (scanData) => {
    if (scanData?.requiresAuth) {
      setPendingScan(scanData);
      setCurrentScan(null);
    } else {
      setPendingScan(null);
      setCurrentScan(scanData);
    }
    // Cập nhật lại stats
    scanAPI.getPublicStats()
      .then((res) => setPublicStats(res.data.stats))
      .catch(() => {});
  };

  const handleAuthSuccess = async (u) => {
    setUser(u);
    if (pendingScan?.scanId) {
      try {
        const res = await scanAPI.claimScan(pendingScan.scanId);
        setCurrentScan(res.data.data);
        setPendingScan(null);
        setActiveTab('scanner');
      } catch (err) {
        alert('Không thể mở kết quả quét: ' + (err.response?.data?.error || err.message));
      }
    }
  };

  const handleViewScanFromHistory = async (scanId) => {
    try {
      const res = await scanAPI.getScanById(scanId);
      setCurrentScan(res.data.data);
      setActiveTab('scanner');
    } catch (err) {
      alert('Không thể tải chi tiết bài quét: ' + (err.response?.data?.error || err.message));
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={(tab) => {
          setActiveTab(tab);
          if (tab !== 'scanner') {
            setCurrentScan(null);
          }
        }}
        user={user}
        onOpenAuth={() => setAuthModalOpen(true)}
        onLogout={handleLogout}
      />

      {/* Main Content Area */}
      <main style={{ flex: 1, paddingBottom: 60 }}>
        {activeTab === 'scanner' && (
          currentScan ? (
            <ScanResultView
              scanData={currentScan}
              onBack={() => setCurrentScan(null)}
            />
          ) : pendingScan ? (
            <div style={{ maxWidth: 640, margin: '60px auto', padding: '0 20px' }}>
              <div className="glass-card" style={{ padding: '40px 28px', textAlign: 'center' }}>
                <div style={{
                  width: 60, height: 60, borderRadius: 16, margin: '0 auto 18px',
                  background: 'linear-gradient(135deg, rgba(244,63,94,0.12), rgba(219,39,119,0.12))',
                  border: '1px solid rgba(219,39,119,0.25)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 26
                }}>
                  🔒
                </div>
                <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 10 }}>
                  Phân tích hoàn tất — Yêu cầu đăng nhập
                </h2>
                <p style={{ color: 'var(--text-muted)', fontSize: 14, lineHeight: 1.6, marginBottom: 22 }}>
                  Hệ thống đã quét xong tệp <strong style={{ color: 'var(--text-main)' }}>{pendingScan.fileName}</strong> cho dự án <strong style={{ color: 'var(--text-main)' }}>{pendingScan.projectName}</strong>.
                  Để bảo mật thông tin lỗ hổng, vui lòng đăng nhập hoặc đăng ký tài khoản để xem báo cáo chi tiết.
                </p>
                <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
                  <button
                    className="btn-primary"
                    onClick={() => setAuthModalOpen(true)}
                  >
                    Đăng Nhập / Đăng Ký Để Xem Kết Quả
                  </button>
                  <button
                    className="btn-secondary"
                    onClick={() => setPendingScan(null)}
                  >
                    Quét tệp khác
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <Scanner
              onScanSuccess={handleScanSuccess}
              stats={publicStats}
            />
          )
        )}

        {activeTab === 'dast' && (
          <DastScanner user={user} onOpenAuth={() => setAuthModalOpen(true)} />
        )}

        {activeTab === 'exploitdb' && (
          <ExploitDbView user={user} />
        )}

        {activeTab === 'history' && (
          <HistoryView
            user={user}
            onViewScan={handleViewScanFromHistory}
            onOpenAuth={() => setAuthModalOpen(true)}
          />
        )}

        {activeTab === 'extension' && (
          <ExtensionView
            user={user}
            onUpdateUser={(updated) => {
              setUser(updated);
              localStorage.setItem('user', JSON.stringify(updated));
            }}
            onOpenAuth={() => setAuthModalOpen(true)}
          />
        )}

        {activeTab === 'admin' && user?.role === 'admin' && (
          <AdminView />
        )}
      </main>

      {/* Footer */}
      <footer style={{
        borderTop: '1px solid #fce7f3',
        padding: '24px 20px',
        textAlign: 'center',
        fontSize: 13,
        color: '#64748b',
        background: '#ffffff',
        boxShadow: '0 -2px 10px rgba(236, 72, 153, 0.03)'
      }}>
        <div style={{ maxWidth: 1200, margin: '0 auto', display: 'flex', justifyContent: 'center', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
          <div style={{ fontFamily: 'var(--font-heading)', fontWeight: 700, color: '#111827', letterSpacing: '0.04em' }}>
            Nền Tảng Đánh Giá An Toàn Chuỗi Cung Ứng & Kiểm Thử DAST
          </div>
        </div>
      </footer>

      {/* Auth Modal */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        onAuthSuccess={handleAuthSuccess}
      />
    </div>
  );
}

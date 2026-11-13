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
    setCurrentScan(scanData);
    // Cập nhật lại stats
    scanAPI.getPublicStats()
      .then((res) => setPublicStats(res.data.stats))
      .catch(() => {});
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
          ) : (
            <Scanner
              onScanSuccess={handleScanSuccess}
              stats={publicStats}
            />
          )
        )}

        {activeTab === 'dast' && (
          <DastScanner />
        )}

        {activeTab === 'exploitdb' && (
          <ExploitDbView />
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
        onAuthSuccess={(u) => setUser(u)}
      />
    </div>
  );
}

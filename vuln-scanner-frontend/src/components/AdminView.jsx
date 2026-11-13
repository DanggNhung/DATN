import React, { useState, useEffect } from 'react';
import { 
  Users, ShieldAlert, RefreshCw, Lock, Unlock, ShieldCheck, 
  UserCheck, AlertTriangle, Search, Database, Flame, Clock 
} from 'lucide-react';
import { adminAPI } from '../services/api';

export default function AdminView() {
  const [overview, setOverview] = useState(null);
  const [users, setUsers] = useState([]);
  const [cisaStatus, setCisaStatus] = useState(null);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [isSyncingCisa, setIsSyncingCisa] = useState(false);
  const [syncMessage, setSyncMessage] = useState('');

  const loadData = async () => {
    setLoading(true);
    try {
      const [ovRes, uRes, cisaRes] = await Promise.all([
        adminAPI.getOverview(),
        adminAPI.getUsers(1, search),
        adminAPI.getCisaStatus()
      ]);
      setOverview(ovRes.data.overview);
      setUsers(uRes.data.data);
      setCisaStatus(cisaRes.data.stats);
    } catch (err) {
      console.error('Lỗi nạp dữ liệu admin:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [search]);

  // Khóa / Mở khóa tài khoản
  const handleToggleStatus = async (userId) => {
    try {
      const res = await adminAPI.toggleUserStatus(userId);
      setUsers((prev) =>
        prev.map((u) => (u._id === userId ? { ...u, isActive: res.data.user.isActive } : u))
      );
    } catch (err) {
      alert(err.response?.data?.error || err.message);
    }
  };

  // Đổi vai trò
  const handleRoleChange = async (userId, currentRole) => {
    const newRole = currentRole === 'admin' ? 'user' : 'admin';
    if (!window.confirm(`Bạn có chắc muốn đổi vai trò người dùng này sang ${newRole}?`)) return;

    try {
      await adminAPI.updateUserRole(userId, newRole);
      setUsers((prev) =>
        prev.map((u) => (u._id === userId ? { ...u, role: newRole } : u))
      );
    } catch (err) {
      alert(err.response?.data?.error || err.message);
    }
  };

  // Đồng bộ CISA KEV Catalog
  const handleSyncCisa = async () => {
    setIsSyncingCisa(true);
    setSyncMessage('');
    try {
      const res = await adminAPI.triggerCisaSync();
      setSyncMessage(`Thành công! Đã nạp ${res.data.details?.count || 1746} lỗ hổng mới nhất từ CISA.`);
      const updatedCisa = await adminAPI.getCisaStatus();
      setCisaStatus(updatedCisa.data.stats);
    } catch (err) {
      setSyncMessage('Lỗi đồng bộ: ' + (err.response?.data?.error || err.message));
    } finally {
      setIsSyncingCisa(false);
    }
  };

  if (loading && !overview) {
    return (
      <div style={{ textAlign: 'center', padding: '80px 0', color: 'var(--cyber-cyan)' }}>
        <RefreshCw size={36} style={{ animation: 'spin 1s linear infinite', margin: '0 auto 12px' }} />
        <div>Đang tải dữ liệu Quản trị Admin...</div>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 1100, margin: '0 auto', padding: '30px 20px' }}>
      {/* Title */}
      <div style={{ marginBottom: 28 }}>
        <h2 style={{ fontSize: 26, fontWeight: 800, display: 'flex', alignItems: 'center', gap: 10 }}>
          <span>Bảng Điều Khiển Quản Trị Hệ Thống</span>
          <span className="badge" style={{ background: 'rgba(139, 92, 246, 0.2)', color: '#c084fc', border: '1px solid rgba(139, 92, 246, 0.4)' }}>
            Admin Maintenance
          </span>
        </h2>
        <p style={{ color: 'var(--text-muted)', fontSize: 14, marginTop: 4 }}>
          Giám sát tình trạng hệ thống, quản lý cơ sở dữ liệu lỗ hổng CISA KEV và người dùng
        </p>
      </div>

      {/* Top Stat Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16, marginBottom: 24 }}>
        <div className="glass-card" style={{ padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 13, color: 'var(--text-dim)' }}>Tổng Người Dùng</span>
            <Users size={18} color="var(--cyber-cyan)" />
          </div>
          <div style={{ fontSize: 26, fontWeight: 800, marginTop: 8 }}>{overview?.totalUsers || 0}</div>
        </div>

        <div className="glass-card" style={{ padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 13, color: 'var(--text-dim)' }}>Tổng Phiên Quét</span>
            <ShieldAlert size={18} color="#f59e0b" />
          </div>
          <div style={{ fontSize: 26, fontWeight: 800, marginTop: 8 }}>{overview?.totalScans || 0}</div>
        </div>

        <div className="glass-card" style={{ padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 13, color: 'var(--text-dim)' }}>Catalog CISA KEV</span>
            <Flame size={18} color="#f87171" />
          </div>
          <div style={{ fontSize: 26, fontWeight: 800, color: '#f87171', marginTop: 8 }}>
            {cisaStatus?.totalKevVulnerabilities || 0} <span style={{ fontSize: 14, fontWeight: 500 }}>CVEs</span>
          </div>
        </div>
      </div>

      {/* CISA KEV Management Card */}
      <div className="glass-card" style={{ padding: 24, marginBottom: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <h3 style={{ fontSize: 18, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Database size={18} color="var(--cyber-purple)" />
              <span>Đồng Bộ Cơ Sở Dữ Liệu CISA KEV Catalog</span>
            </h3>
            <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Clock size={14} />
              <span>Thời gian đồng bộ gần nhất: {cisaStatus?.lastSynced ? new Date(cisaStatus.lastSynced).toLocaleString('vi-VN') : 'Mới khởi tạo'}</span>
              <span>• Đã nạp RAM: <strong>{cisaStatus?.inMemoryCached || 0}</strong> CVEs</span>
            </div>
          </div>

          <button
            onClick={handleSyncCisa}
            disabled={isSyncingCisa}
            className="btn-primary"
            style={{ background: 'linear-gradient(135deg, #8b5cf6, #3b82f6)' }}
          >
            <RefreshCw size={15} style={{ animation: isSyncingCisa ? 'spin 1s linear infinite' : 'none' }} />
            <span>{isSyncingCisa ? 'Đang Đồng Bộ Dữ Liệu...' : 'Đồng Bộ Danh Mục CISA Ngay'}</span>
          </button>
        </div>

        {syncMessage && (
          <div style={{
            marginTop: 14,
            padding: '10px 14px',
            borderRadius: 6,
            background: 'rgba(16, 185, 129, 0.1)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            color: '#34d399',
            fontSize: 13
          }}>
            {syncMessage}
          </div>
        )}
      </div>

      {/* User Management Section */}
      <div className="glass-card" style={{ padding: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 14, marginBottom: 18 }}>
          <h3 style={{ fontSize: 18, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Users size={18} color="var(--cyber-cyan)" />
            <span>Danh Sách Người Dùng & Quản Trị Viên</span>
          </h3>

          <div style={{ position: 'relative', width: 280 }}>
            <Search size={15} color="var(--text-dim)" style={{ position: 'absolute', left: 12, top: 10 }} />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Tìm theo username hoặc email..."
              style={{
                width: '100%',
                background: 'var(--bg-primary)',
                border: '1px solid var(--border-subtle)',
                padding: '7px 12px 7px 34px',
                borderRadius: 8,
                color: 'var(--text-main)',
                fontSize: 13,
                outline: 'none'
              }}
            />
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)', background: 'rgba(255,255,255,0.02)' }}>
                <th style={{ padding: '12px 16px', color: 'var(--text-dim)' }}>NGƯỜI DÙNG</th>
                <th style={{ padding: '12px 16px', color: 'var(--text-dim)' }}>EMAIL</th>
                <th style={{ padding: '12px 16px', color: 'var(--text-dim)' }}>VAI TRÒ</th>
                <th style={{ padding: '12px 16px', color: 'var(--text-dim)' }}>TRẠNG THÁI</th>
                <th style={{ padding: '12px 16px', color: 'var(--text-dim)' }}>API KEY</th>
                <th style={{ padding: '12px 16px', textAlign: 'right', color: 'var(--text-dim)' }}>HÀNH ĐỘNG</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u._id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '12px 16px', fontWeight: 600 }}>
                    {u.username}
                  </td>
                  <td style={{ padding: '12px 16px', color: 'var(--text-muted)' }}>
                    {u.email}
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <span className={`badge ${u.role === 'admin' ? 'badge-cisa' : 'badge-low'}`}>
                      {u.role === 'admin' ? 'ADMIN (DUY NHẤT)' : 'KHÁCH (USER)'}
                    </span>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    {u.isActive ? (
                      <span className="badge badge-safe">Hoạt động</span>
                    ) : (
                      <span className="badge badge-critical">Đã khóa</span>
                    )}
                  </td>
                  <td style={{ padding: '12px 16px' }} className="mono" title={u.apiKey}>
                    {u.apiKey ? `${u.apiKey.substring(0, 10)}...` : 'Chưa cấp'}
                  </td>
                  <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: 8 }}>
                      {u.role !== 'admin' ? (
                        <button
                          onClick={() => handleToggleStatus(u._id)}
                          className={u.isActive ? 'btn-danger' : 'btn-secondary'}
                          style={{ padding: '5px 10px', fontSize: 11 }}
                          title={u.isActive ? 'Khóa tài khoản khách' : 'Mở khóa tài khoản khách'}
                        >
                          {u.isActive ? <Lock size={12} /> : <Unlock size={12} />}
                          <span>{u.isActive ? 'Khóa khách' : 'Mở khóa'}</span>
                        </button>
                      ) : (
                        <span style={{ fontSize: 11, color: 'var(--text-dim)', fontStyle: 'italic' }}>
                          Quản trị viên chính
                        </span>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

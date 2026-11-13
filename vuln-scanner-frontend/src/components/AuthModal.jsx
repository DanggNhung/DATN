import React, { useState } from 'react';
import { X, Lock, Mail, User, ShieldAlert, ArrowRight } from 'lucide-react';
import { authAPI } from '../services/api';

export default function AuthModal({ isOpen, onClose, onAuthSuccess }) {
  const [tab, setTab] = useState('login'); // 'login' | 'register'
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    emailOrUsername: ''
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
    setError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      let res;
      if (tab === 'login') {
        res = await authAPI.login({
          emailOrUsername: formData.emailOrUsername,
          password: formData.password
        });
      } else {
        res = await authAPI.register({
          username: formData.username,
          email: formData.email,
          password: formData.password
        });
      }

      const { token, user } = res.data;
      localStorage.setItem('token', token);
      localStorage.setItem('user', JSON.stringify(user));

      onAuthSuccess(user);
      onClose();
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Lỗi xác thực');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="glass-card"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: 420,
          padding: 28,
          position: 'relative',
          background: '#101624',
          boxShadow: '0 20px 50px rgba(0, 0, 0, 0.7)'
        }}
      >
        {/* Close Button */}
        <button
          onClick={onClose}
          style={{
            position: 'absolute',
            top: 18,
            right: 18,
            background: 'transparent',
            border: 'none',
            color: 'var(--text-dim)',
            cursor: 'pointer'
          }}
        >
          <X size={20} />
        </button>

        {/* Modal Header */}
        <div style={{ textAlign: 'center', marginBottom: 20 }}>
          <div style={{
            width: 44,
            height: 44,
            borderRadius: 12,
            background: 'linear-gradient(135deg, #06b6d4, #3b82f6)',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: 10
          }}>
            <ShieldAlert size={24} color="#ffffff" />
          </div>
          <h3 style={{ fontSize: 20, fontWeight: 800 }}>
            {tab === 'login' ? 'Đăng Nhập Tài Khoản' : 'Tạo Tài Khoản Mới'}
          </h3>
          <p style={{ fontSize: 13, color: 'var(--text-dim)', marginTop: 4 }}>
            {tab === 'login' ? 'Truy cập báo cáo bảo mật và quản lý API Key' : 'Bắt đầu kiểm thử chuỗi cung ứng mã nguồn'}
          </p>
        </div>

        {/* Tabs */}
        <div style={{
          display: 'flex',
          background: 'var(--bg-primary)',
          borderRadius: 8,
          padding: 4,
          marginBottom: 20
        }}>
          <button
            type="button"
            onClick={() => { setTab('login'); setError(''); }}
            style={{
              flex: 1,
              padding: '8px 0',
              border: 'none',
              borderRadius: 6,
              background: tab === 'login' ? 'var(--bg-tertiary)' : 'transparent',
              color: tab === 'login' ? 'var(--cyber-cyan)' : 'var(--text-dim)',
              fontWeight: 600,
              fontSize: 13,
              cursor: 'pointer'
            }}
          >
            Đăng Nhập
          </button>
          <button
            type="button"
            onClick={() => { setTab('register'); setError(''); }}
            style={{
              flex: 1,
              padding: '8px 0',
              border: 'none',
              borderRadius: 6,
              background: tab === 'register' ? 'var(--bg-tertiary)' : 'transparent',
              color: tab === 'register' ? 'var(--cyber-cyan)' : 'var(--text-dim)',
              fontWeight: 600,
              fontSize: 13,
              cursor: 'pointer'
            }}
          >
            Đăng Ký
          </button>
        </div>

        {/* Error message */}
        {error && (
          <div style={{
            marginBottom: 16,
            padding: '10px 12px',
            borderRadius: 6,
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            color: '#f87171',
            fontSize: 13
          }}>
            {error}
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {tab === 'register' && (
            <div>
              <label style={{ display: 'block', fontSize: 12, color: 'var(--text-dim)', marginBottom: 5 }}>
                Tên người dùng (Username)
              </label>
              <div style={{ position: 'relative' }}>
                <User size={16} color="var(--text-dim)" style={{ position: 'absolute', left: 12, top: 12 }} />
                <input
                  type="text"
                  name="username"
                  required
                  value={formData.username}
                  onChange={handleChange}
                  placeholder="admin, developer1..."
                  style={{
                    width: '100%',
                    background: 'var(--bg-primary)',
                    border: '1px solid var(--border-subtle)',
                    padding: '10px 12px 10px 36px',
                    borderRadius: 8,
                    color: 'var(--text-main)',
                    fontSize: 13,
                    outline: 'none'
                  }}
                />
              </div>
            </div>
          )}

          {tab === 'register' ? (
            <div>
              <label style={{ display: 'block', fontSize: 12, color: 'var(--text-dim)', marginBottom: 5 }}>
                Địa chỉ Email
              </label>
              <div style={{ position: 'relative' }}>
                <Mail size={16} color="var(--text-dim)" style={{ position: 'absolute', left: 12, top: 12 }} />
                <input
                  type="email"
                  name="email"
                  required
                  value={formData.email}
                  onChange={handleChange}
                  placeholder="dev@example.com"
                  style={{
                    width: '100%',
                    background: 'var(--bg-primary)',
                    border: '1px solid var(--border-subtle)',
                    padding: '10px 12px 10px 36px',
                    borderRadius: 8,
                    color: 'var(--text-main)',
                    fontSize: 13,
                    outline: 'none'
                  }}
                />
              </div>
            </div>
          ) : (
            <div>
              <label style={{ display: 'block', fontSize: 12, color: 'var(--text-dim)', marginBottom: 5 }}>
                Tên người dùng hoặc Email
              </label>
              <div style={{ position: 'relative' }}>
                <User size={16} color="var(--text-dim)" style={{ position: 'absolute', left: 12, top: 12 }} />
                <input
                  type="text"
                  name="emailOrUsername"
                  required
                  value={formData.emailOrUsername}
                  onChange={handleChange}
                  placeholder="admin hoặc email@example.com"
                  style={{
                    width: '100%',
                    background: 'var(--bg-primary)',
                    border: '1px solid var(--border-subtle)',
                    padding: '10px 12px 10px 36px',
                    borderRadius: 8,
                    color: 'var(--text-main)',
                    fontSize: 13,
                    outline: 'none'
                  }}
                />
              </div>
            </div>
          )}

          <div>
            <label style={{ display: 'block', fontSize: 12, color: 'var(--text-dim)', marginBottom: 5 }}>
              Mật khẩu
            </label>
            <div style={{ position: 'relative' }}>
              <Lock size={16} color="var(--text-dim)" style={{ position: 'absolute', left: 12, top: 12 }} />
              <input
                type="password"
                name="password"
                required
                value={formData.password}
                onChange={handleChange}
                placeholder="••••••••"
                style={{
                  width: '100%',
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border-subtle)',
                  padding: '10px 12px 10px 36px',
                  borderRadius: 8,
                  color: 'var(--text-main)',
                  fontSize: 13,
                  outline: 'none'
                }}
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn-primary"
            style={{ width: '100%', justifyContent: 'center', marginTop: 10, padding: 12 }}
          >
            <span>{loading ? 'Đang Xử Lý...' : tab === 'login' ? 'Đăng Nhập' : 'Tạo Tài Khoản'}</span>
            <ArrowRight size={16} />
          </button>
        </form>
      </div>
    </div>
  );
}

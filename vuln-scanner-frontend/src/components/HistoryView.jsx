import React, { useState, useEffect } from 'react';
import { History, Eye, ArrowRight, RefreshCw, AlertTriangle, ShieldCheck, Terminal, Globe } from 'lucide-react';
import { scanAPI } from '../services/api';

function decodeUtf8Safe(str) {
  if (!str) return '';
  try {
    if (/[ÄÅá»º·]/.test(str)) {
      return decodeURIComponent(escape(str));
    }
  } catch (e) {}
  return str;
}

export default function HistoryView({ user, onViewScan, onOpenAuth }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [error, setError] = useState('');

  const fetchHistory = async () => {
    if (!user) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const res = await scanAPI.getHistory(page, 10);
      setScans(res.data.data);
      setTotalPages(res.data.pagination.pages || 1);
      setError('');
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [user, page]);

  if (!user) {
    return (
      <div style={{ maxWidth: 700, margin: '60px auto', textAlign: 'center', padding: 20 }}>
        <div className="glass-card" style={{ padding: 40 }}>
          <History size={48} color="var(--cyber-cyan)" style={{ margin: '0 auto 16px' }} />
          <h2 style={{ fontSize: 22, fontWeight: 700 }}>Đăng nhập để xem lịch sử quét</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: 14, marginTop: 8, marginBottom: 24 }}>
            Lịch sử các lần quét dự án của bạn và từ VS Code Extension sẽ được lưu trữ an toàn trong tài khoản của bạn.
          </p>
          <button onClick={onOpenAuth} className="btn-primary" style={{ margin: '0 auto' }}>
            <span>Đăng Nhập Ngay</span>
            <ArrowRight size={16} />
          </button>
        </div>
      </div>
    );
  }

  const getRiskBadge = (level) => {
    switch (level) {
      case 'CRITICAL': return <span className="badge badge-critical">CRITICAL</span>;
      case 'HIGH': return <span className="badge badge-high">HIGH</span>;
      case 'MEDIUM': return <span className="badge badge-medium">MEDIUM</span>;
      case 'LOW': return <span className="badge badge-low">LOW</span>;
      case 'INCONCLUSIVE': return <span className="badge" style={{ background: 'rgba(249, 115, 22, 0.2)', color: '#f97316', border: '1px solid #f97316' }}>INCONCLUSIVE</span>;
      default: return <span className="badge badge-safe">SAFE</span>;
    }
  };

  return (
    <div style={{ maxWidth: 1050, margin: '0 auto', padding: '30px 20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h2 style={{ fontSize: 24, fontWeight: 800 }}>Lịch Sử Quét Bảo Mật</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: 14, marginTop: 4 }}>
            Quản lý các phiên phân tích mã nguồn và kiểm thử chuỗi cung ứng
          </p>
        </div>

        <button onClick={fetchHistory} className="btn-secondary" style={{ padding: '8px 14px', fontSize: 13 }}>
          <RefreshCw size={14} />
          <span>Làm mới</span>
        </button>
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--cyber-cyan)' }}>
          <RefreshCw size={32} style={{ animation: 'spin 1s linear infinite', margin: '0 auto 12px' }} />
          <div>Đang tải danh sách lịch sử...</div>
        </div>
      ) : error ? (
        <div className="glass-card" style={{ padding: 20, color: '#f87171' }}>
          {error}
        </div>
      ) : scans.length === 0 ? (
        <div className="glass-card" style={{ padding: 40, textAlign: 'center', color: 'var(--text-dim)' }}>
          <History size={40} style={{ margin: '0 auto 12px', opacity: 0.5 }} />
          <div style={{ fontSize: 16 }}>Chưa có phiên quét nào được ghi nhận</div>
          <div style={{ fontSize: 13, marginTop: 4 }}>Hãy tải lên tệp đầu tiên để kiểm thử bảo mật!</div>
        </div>
      ) : (
        <div className="glass-card table-responsive" style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', minWidth: 700, borderCollapse: 'collapse', textAlign: 'left', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)', background: 'rgba(255,255,255,0.02)' }}>
                <th style={{ padding: '14px 18px', color: 'var(--text-dim)', fontWeight: 600 }}>DỰ ÁN</th>
                <th style={{ padding: '14px 18px', color: 'var(--text-dim)', fontWeight: 600 }}>TỆP QUÉT</th>
                <th style={{ padding: '14px 18px', color: 'var(--text-dim)', fontWeight: 600 }}>NGUỒN</th>
                <th style={{ padding: '14px 18px', color: 'var(--text-dim)', fontWeight: 600 }}>TỔNG THƯ VIỆN</th>
                <th style={{ padding: '14px 18px', color: 'var(--text-dim)', fontWeight: 600 }}>MỨC ĐỘ RỦI RO</th>
                <th style={{ padding: '14px 18px', color: 'var(--text-dim)', fontWeight: 600 }}>THỜI GIAN</th>
                <th style={{ padding: '14px 18px', textAlign: 'right', color: 'var(--text-dim)', fontWeight: 600 }}>THAO TÁC</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan._id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '14px 18px', fontWeight: 600 }}>
                    {decodeUtf8Safe(scan.projectName)}
                  </td>
                  <td style={{ padding: '14px 18px' }} className="mono">
                    {decodeUtf8Safe(scan.fileName)}
                  </td>
                  <td style={{ padding: '14px 18px' }}>
                    {scan.source === 'vscode_extension' ? (
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, color: '#38bdf8' }}>
                        <Terminal size={14} /> VS Code
                      </span>
                    ) : (
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, color: 'var(--text-muted)' }}>
                        <Globe size={14} /> Web Portal
                      </span>
                    )}
                  </td>
                  <td style={{ padding: '14px 18px' }}>
                    <strong>{scan.summary?.totalPackages || 0}</strong> ({scan.summary?.vulnerablePackages || 0} dính lỗi)
                  </td>
                  <td style={{ padding: '14px 18px' }}>
                    {getRiskBadge(scan.summary?.riskLevel)}
                  </td>
                  <td style={{ padding: '14px 18px', color: 'var(--text-dim)', fontSize: 12 }}>
                    {new Date(scan.createdAt).toLocaleString('vi-VN')}
                  </td>
                  <td style={{ padding: '14px 18px', textAlign: 'right' }}>
                    <button
                      onClick={() => onViewScan(scan._id)}
                      className="btn-secondary"
                      style={{ padding: '6px 12px', fontSize: 12 }}
                    >
                      <Eye size={13} />
                      <span>Xem</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

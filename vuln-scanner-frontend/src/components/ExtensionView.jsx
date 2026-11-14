import React, { useState } from 'react';
import { Terminal, Key, Copy, Check, Download, RefreshCw, AlertCircle, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { authAPI } from '../services/api';

export default function ExtensionView({ user, onUpdateUser, onOpenAuth }) {
  const [copied, setCopied] = useState(false);
  const [isRegenerating, setIsRegenerating] = useState(false);

  const handleCopyKey = () => {
    if (user?.apiKey) {
      navigator.clipboard.writeText(user.apiKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleRegenerateKey = async () => {
    if (!window.confirm('Bạn có chắc chắn muốn làm mới API Key? Các extension đang dùng key cũ sẽ cần cập nhật lại!')) {
      return;
    }
    setIsRegenerating(true);
    try {
      const res = await authAPI.regenerateApiKey();
      onUpdateUser({ ...user, apiKey: res.data.apiKey });
    } catch (err) {
      alert('Lỗi tạo mới API Key: ' + err.message);
    } finally {
      setIsRegenerating(false);
    }
  };

  return (
    <div style={{ maxWidth: 900, margin: '0 auto', padding: '30px 20px' }}>
      {/* Title */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ padding: 10, borderRadius: 10, background: 'rgba(6, 182, 212, 0.15)', color: 'var(--cyber-cyan)' }}>
            <Terminal size={24} />
          </div>
          <div>
            <h2 style={{ fontSize: 24, fontWeight: 800 }}>Tích Hợp VS Code Extension (Shift-Left Security)</h2>
            <p style={{ color: 'var(--text-muted)', fontSize: 14, marginTop: 2 }}>
              Phát hiện lỗ hổng và rủi ro chuỗi cung ứng ngay trong khi bạn đang viết mã tại VS Code
            </p>
          </div>
        </div>
      </div>

      {/* API Key Box */}
      <div className="glass-card" style={{ padding: 24, marginBottom: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Key size={18} color="var(--cyber-cyan)" />
            <h3 style={{ fontSize: 16, fontWeight: 700 }}>API Key Của Bạn</h3>
          </div>
          {user && (
            <button
              onClick={handleRegenerateKey}
              disabled={isRegenerating}
              className="btn-secondary"
              style={{ padding: '6px 12px', fontSize: 12 }}
            >
              <RefreshCw size={13} style={{ animation: isRegenerating ? 'spin 1s linear infinite' : 'none' }} />
              <span>Tạo lại Key mới</span>
            </button>
          )}
        </div>

        {user ? (
          <div>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              background: 'var(--bg-primary)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 8,
              padding: '10px 14px',
              gap: 12
            }}>
              <span className="mono" style={{ fontSize: 14, color: 'var(--cyber-cyan)', flex: 1, wordBreak: 'break-all' }}>
                {user.apiKey}
              </span>
              <button
                onClick={handleCopyKey}
                className="btn-secondary"
                style={{ padding: '6px 12px', fontSize: 12, flexShrink: 0 }}
              >
                {copied ? <Check size={14} color="#34d399" /> : <Copy size={14} />}
                <span>{copied ? 'Đã sao chép!' : 'Sao chép'}</span>
              </button>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 8 }}>
              * Giữ API Key bí mật. Dùng Key này để kết nối plugin VS Code với tài khoản của bạn.
            </div>
          </div>
        ) : (
          <div style={{ padding: '16px 0', textAlign: 'center' }}>
            <p style={{ color: 'var(--text-muted)', fontSize: 14, marginBottom: 14 }}>
              Bạn cần đăng nhập để lấy API Key kích hoạt VS Code Extension.
            </p>
            <button onClick={onOpenAuth} className="btn-primary" style={{ padding: '8px 18px', fontSize: 13 }}>
              <span>Đăng Nhập Để Nhận API Key</span>
            </button>
          </div>
        )}
      </div>

      {/* Download Section */}
      <div className="glass-card" style={{ padding: 24, marginBottom: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <h3 style={{ fontSize: 18, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
              <span>Gói Cài Đặt Extension (.vsix)</span>
              <span className="badge badge-safe">Phiên bản v1.0.0</span>
            </h3>
            <p style={{ color: 'var(--text-muted)', fontSize: 13, marginTop: 4 }}>
              Đóng gói độc lập, tương thích với mọi phiên bản VS Code (Windows, macOS, Linux)
            </p>
          </div>

          <a
            href="/secshield-scanner-1.0.0.vsix"
            download="secshield-scanner-1.0.0.vsix"
            className="btn-primary"
            style={{ textDecoration: 'none' }}
          >
            <Download size={16} />
            <span>Tải Về Gói secshield-scanner.vsix</span>
          </a>
        </div>
      </div>

      {/* Step by step installation guide */}
      <div className="glass-card" style={{ padding: 24 }}>
        <h3 style={{ fontSize: 18, fontWeight: 700, marginBottom: 18 }}>
          Hướng Dẫn Cài Đặt & Sử Dụng Trong 3 Bước
        </h3>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Step 1 */}
          <div style={{ display: 'flex', gap: 16 }}>
            <div style={{
              width: 32,
              height: 32,
              borderRadius: '50%',
              background: 'rgba(6, 182, 212, 0.2)',
              color: 'var(--cyber-cyan)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontWeight: 800,
              flexShrink: 0
            }}>
              1
            </div>
            <div>
              <div style={{ fontWeight: 700, fontSize: 15 }}>Cài đặt file .vsix vào VS Code</div>
              <div style={{ color: 'var(--text-muted)', fontSize: 13, marginTop: 4 }}>
                Mở VS Code ➔ bấm tổ hợp phím <kbd style={{ background: 'var(--bg-primary)', padding: '2px 6px', borderRadius: 4, border: '1px solid var(--border-subtle)' }}>Ctrl+Shift+P</kbd> ➔ gõ:
              </div>
              <div style={{
                background: 'var(--bg-primary)',
                padding: '8px 12px',
                borderRadius: 6,
                fontFamily: 'var(--font-mono)',
                fontSize: 13,
                color: '#38bdf8',
                marginTop: 6
              }}>
                Extensions: Install from VSIX...
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 4 }}>
                Hoặc chạy qua terminal: <code className="mono">code --install-extension secshield-scanner-1.0.0.vsix</code>
              </div>
            </div>
          </div>

          {/* Step 2 */}
          <div style={{ display: 'flex', gap: 16 }}>
            <div style={{
              width: 32,
              height: 32,
              borderRadius: '50%',
              background: 'rgba(6, 182, 212, 0.2)',
              color: 'var(--cyber-cyan)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontWeight: 800,
              flexShrink: 0
            }}>
              2
            </div>
            <div>
              <div style={{ fontWeight: 700, fontSize: 15 }}>Cấu hình API Key</div>
              <div style={{ color: 'var(--text-muted)', fontSize: 13, marginTop: 4 }}>
                Bấm <kbd style={{ background: 'var(--bg-primary)', padding: '2px 6px', borderRadius: 4, border: '1px solid var(--border-subtle)' }}>Ctrl+Shift+P</kbd> ➔ chọn <strong style={{ color: 'var(--text-main)' }}>SecShield: Set API Key</strong> và dán mã API Key phía trên vào.
              </div>
            </div>
          </div>

          {/* Step 3 */}
          <div style={{ display: 'flex', gap: 16 }}>
            <div style={{
              width: 32,
              height: 32,
              borderRadius: '50%',
              background: 'rgba(6, 182, 212, 0.2)',
              color: 'var(--cyber-cyan)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontWeight: 800,
              flexShrink: 0
            }}>
              3
            </div>
            <div>
              <div style={{ fontWeight: 700, fontSize: 15 }}>Quét bảo mật tự động</div>
              <div style={{ color: 'var(--text-muted)', fontSize: 13, marginTop: 4 }}>
                Mở tệp <code className="mono" style={{ color: 'var(--cyber-cyan)' }}>package.json</code> hoặc <code className="mono" style={{ color: 'var(--cyber-cyan)' }}>requirements.txt</code> trong dự án ➔ Click chuột phải chọn:
              </div>
              <div style={{
                background: 'var(--bg-primary)',
                padding: '8px 12px',
                borderRadius: 6,
                fontFamily: 'var(--font-mono)',
                fontSize: 13,
                color: '#34d399',
                marginTop: 6
              }}>
                🛡️ SecShield: Scan Project Dependencies
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 4 }}>
                Kết quả các thư viện dính mã độc và CVE sẽ hiện ngay trong bảng Problems của VS Code.
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

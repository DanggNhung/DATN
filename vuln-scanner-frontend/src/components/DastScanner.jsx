import React, { useState, useEffect } from 'react';
import {
  Zap, Globe, ShieldAlert, AlertTriangle, CheckCircle, RefreshCw,
  ArrowRight, ArrowLeft, ExternalLink, ShieldCheck, Flame, Wrench, Bug, Play
} from 'lucide-react';
import { dastAPI } from '../services/api';

export default function DastScanner({ user, onOpenAuth }) {
  const [targetUrl, setTargetUrl] = useState('');
  const [projectName, setProjectName] = useState('');
  const [zapStatus, setZapStatus] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [scanResult, setScanResult] = useState(null);
  const [pendingDastScan, setPendingDastScan] = useState(null);
  const [errorMessage, setErrorMessage] = useState('');

  const scanSteps = [
    'Đang gửi gói tin thăm dò cấu trúc Endpoint...',
    'Đang kiểm thử bộ lọc bảo vệ HTTP Headers (CSP, HSTS, X-Frame-Options)...',
    'Đang giả lập tấn công vượt rào CORS (Origin Reflection Attack)...',
    'Đang kiểm thử phá vỡ phương thức HTTP (HTTP Verb Tampering & TRACE)...',
    'Đang bắn tham số dị thường kiểm tra rò rỉ Stack Trace / Ngoại lệ hệ thống...'
  ];

  // Kiểm tra tình trạng ZAP khi tải trang
  useEffect(() => {
    dastAPI.getZapStatus()
      .then((res) => setZapStatus(res.data.status))
      .catch(() => setZapStatus({ isAvailable: false }));
  }, []);

  // Tự động mở kết quả DAST sau khi khách đăng nhập thành công
  useEffect(() => {
    if (user && pendingDastScan?.scanId) {
      dastAPI.claimScan(pendingDastScan.scanId)
        .then((res) => {
          setScanResult(res.data.data);
          setPendingDastScan(null);
        })
        .catch((err) => {
          setErrorMessage(err.response?.data?.error || 'Không thể tải kết quả kiểm thử DAST');
          setPendingDastScan(null);
        });
    }
  }, [user, pendingDastScan]);

  const handleDemoLocal = () => {
    setTargetUrl('http://localhost:5000/health');
    setProjectName('SecShield Internal Health Service');
    setErrorMessage('');
  };

  const handleDemoTestApi = () => {
    setTargetUrl('https://httpbin.org/get');
    setProjectName('HTTPBin Public Echo API');
    setErrorMessage('');
  };

  const runDastScan = async (e) => {
    e.preventDefault();
    if (!targetUrl.trim()) {
      setErrorMessage('Vui lòng nhập URL Endpoint cần kiểm thử!');
      return;
    }

    setErrorMessage('');
    setIsScanning(true);
    setScanStep(0);
    setScanResult(null);

    const stepTimer = setInterval(() => {
      setScanStep((prev) => (prev < scanSteps.length - 1 ? prev + 1 : prev));
    }, 600);

    try {
      const res = await dastAPI.scan({
        targetUrl: targetUrl.trim(),
        projectName: projectName.trim() || 'API Security Scan'
      });
      clearInterval(stepTimer);
      setIsScanning(false);
      if (res.data?.requiresAuth) {
        setPendingDastScan(res.data);
      } else {
        setPendingDastScan(null);
        setScanResult(res.data);
      }
    } catch (err) {
      clearInterval(stepTimer);
      setIsScanning(false);
      setErrorMessage(err.response?.data?.error || err.message || 'Lỗi kiểm thử DAST');
    }
  };

  const getRiskBadge = (risk) => {
    switch (risk) {
      case 'High': return <span className="badge badge-critical">HIGH RISK</span>;
      case 'Medium': return <span className="badge badge-high">MEDIUM</span>;
      case 'Low': return <span className="badge badge-medium">LOW</span>;
      default: return <span className="badge badge-low">INFO</span>;
    }
  };

  const getGradeColor = (grade) => {
    switch (grade) {
      case 'A+':
      case 'A': return '#10b981';
      case 'B': return '#3b82f6';
      case 'C': return '#f59e0b';
      default: return '#ef4444';
    }
  };

  return (
    <div style={{ maxWidth: 950, margin: '0 auto', padding: '30px 20px' }}>
      {/* Title */}
      <div style={{ textAlign: 'center', marginBottom: 30 }}>
        <div style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
          background: 'rgba(239, 68, 68, 0.1)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          color: '#f87171',
          padding: '4px 12px',
          borderRadius: 20,
          fontSize: 12,
          fontWeight: 600,
          marginBottom: 14
        }}>
          <Zap size={14} /> DAST Active Security Assessment Engine
        </div>
        <h1 style={{ fontSize: 30, fontWeight: 800, letterSpacing: '-0.02em', marginBottom: 10 }}>
          Kiểm Thử Động REST API & Tấn Công Thực Nghiệm <span style={{
            background: 'linear-gradient(135deg, #06b6d4, #3b82f6)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent'
          }}>OWASP ZAP</span>
        </h1>
        <p style={{ color: 'var(--text-muted)', fontSize: 14, maxWidth: 650, margin: '0 auto' }}>
          Mô phỏng tấn công thực nghiệm vào các Endpoint API đang chạy để phát hiện các lỗ hổng cấu hình sai, rò rỉ dữ liệu, CORS và OWASP Top 10 API Security Risks.
        </p>

        {/* Engine Status Banner */}
        <div style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 10,
          marginTop: 16,
          padding: '6px 14px',
          borderRadius: 8,
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border-subtle)',
          fontSize: 12
        }}>
          <span style={{ color: 'var(--text-dim)' }}>Engine Tấn Công:</span>
          {zapStatus?.isAvailable ? (
            <span style={{ color: '#34d399', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: 5 }}>
              <CheckCircle size={13} /> OWASP ZAP v{zapStatus.version} (Cổng 8080 Online)
            </span>
          ) : (
            <span style={{ color: '#38bdf8', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 5 }}>
              <ShieldCheck size={13} /> SecShield Automated DAST Engine (Tích hợp sẵn)
            </span>
          )}
        </div>
      </div>

      {/* Main Scanner Card / Input Box */}
      {pendingDastScan && !scanResult ? (
        <div className="glass-card" style={{ padding: '40px 28px', textAlign: 'center' }}>
          <div style={{
            width: 60, height: 60, borderRadius: 16, margin: '0 auto 18px',
            background: 'rgba(59, 130, 246, 0.12)',
            border: '1px solid rgba(59, 130, 246, 0.3)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 26
          }}>
            🔒
          </div>
          <h2 style={{ fontSize: 22, fontWeight: 800, marginBottom: 10 }}>
            Kiểm thử DAST hoàn tất — Yêu cầu đăng nhập
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: 14, lineHeight: 1.6, marginBottom: 22 }}>
            Đã hoàn tất kiểm thử động cho <strong style={{ color: 'var(--text-main)' }}>{pendingDastScan.targetUrl}</strong>.
            Vui lòng đăng nhập hoặc đăng ký tài khoản để xem chi tiết các lỗ hổng phát hiện được.
          </p>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
            <button type="button" className="btn-primary" onClick={onOpenAuth}>
              Đăng Nhập / Đăng Ký Để Xem Kết Quả
            </button>
            <button type="button" className="btn-secondary" onClick={() => setPendingDastScan(null)}>
              Kiểm thử URL khác
            </button>
          </div>
        </div>
      ) : !scanResult ? (
        <div className="glass-card" style={{ padding: 28 }}>
          <form onSubmit={runDastScan}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, marginBottom: 16 }}>
              <label style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-main)' }}>
                Địa Chỉ URL Endpoint Cần Kiểm Thử (Target URL)
              </label>

              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <button
                  type="button"
                  onClick={handleDemoLocal}
                  style={{
                    background: 'rgba(6, 182, 212, 0.1)',
                    color: 'var(--cyber-cyan)',
                    border: '1px solid rgba(6, 182, 212, 0.3)',
                    padding: '4px 10px',
                    borderRadius: 6,
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  Demo API Localhost
                </button>
                <button
                  type="button"
                  onClick={handleDemoTestApi}
                  style={{
                    background: 'rgba(59, 130, 246, 0.1)',
                    color: '#60a5fa',
                    border: '1px solid rgba(59, 130, 246, 0.3)',
                    padding: '4px 10px',
                    borderRadius: 6,
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  Demo API Public
                </button>
              </div>
            </div>

            <div style={{ position: 'relative', marginBottom: 18 }}>
              <Globe size={18} color="var(--text-dim)" style={{ position: 'absolute', left: 14, top: 13 }} />
              <input
                type="text"
                required
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="http://localhost:5000/health hoặc https://my-service.com/api/users"
                style={{
                  width: '100%',
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border-subtle)',
                  padding: '12px 14px 12px 42px',
                  borderRadius: 8,
                  color: 'var(--text-main)',
                  fontSize: 14,
                  fontFamily: 'var(--font-mono)',
                  outline: 'none'
                }}
              />
            </div>

            <div style={{ marginBottom: 22 }}>
              <label style={{ display: 'block', fontSize: 13, color: 'var(--text-muted)', marginBottom: 6, fontWeight: 500 }}>
                Tên dự án / Dịch vụ (Project Name)
              </label>
              <input
                type="text"
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                placeholder="Ví dụ: Payment Microservice API, User Authentication API..."
                style={{
                  width: '100%',
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border-subtle)',
                  padding: '10px 14px',
                  borderRadius: 8,
                  color: 'var(--text-main)',
                  fontSize: 13,
                  outline: 'none'
                }}
              />
            </div>

            {/* Error banner */}
            {errorMessage && (
              <div style={{
                marginBottom: 16,
                padding: '12px 16px',
                borderRadius: 8,
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                color: '#f87171',
                fontSize: 13,
                display: 'flex',
                alignItems: 'center',
                gap: 8
              }}>
                <AlertTriangle size={16} />
                <span>{errorMessage}</span>
              </div>
            )}

            {/* Scanning Progress */}
            {isScanning ? (
              <div style={{ textAlign: 'center', padding: '24px 0' }} className="radar-scanner">
                <RefreshCw size={36} color="#f87171" style={{ animation: 'spin 1s linear infinite', margin: '0 auto 14px' }} />
                <div style={{ fontSize: 16, fontWeight: 700, color: '#f87171' }}>
                  {scanSteps[scanStep]}
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 6 }}>
                  Đang thực thi các kịch bản kiểm thử động và ghi nhận phản hồi từ server...
                </div>
              </div>
            ) : (
              <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                <button
                  type="submit"
                  className="btn-primary"
                  style={{ background: 'linear-gradient(135deg, #ef4444, #dc2626)', boxShadow: '0 0 15px rgba(239, 68, 68, 0.4)' }}
                >
                  <Zap size={16} />
                  <span>Bắt Đầu Kiểm Thử Động (DAST Attack)</span>
                  <ArrowRight size={16} />
                </button>
              </div>
            )}
          </form>
        </div>
      ) : (
        /* DAST Results View */
        <div>
          {/* Back button */}
          <button
            onClick={() => setScanResult(null)}
            className="btn-secondary"
            style={{ marginBottom: 18, padding: '7px 12px', fontSize: 13 }}
          >
            <ArrowLeft size={15} />
            <span>Kiểm Thử Endpoint Khác</span>
          </button>

          {/* DAST Overview Card */}
          <div className="glass-card" style={{ padding: 26, marginBottom: 22, borderTop: `4px solid ${getGradeColor(scanResult.summary.grade)}` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
              <div>
                <div style={{ fontSize: 12, color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 700 }}>
                  Kết Quả Kiểm Thử Động (DAST Assessment)
                </div>
                <h2 style={{ fontSize: 22, fontWeight: 800, marginTop: 4 }}>
                  {scanResult.projectName}
                </h2>
                <div style={{ fontSize: 13, color: 'var(--text-dim)', marginTop: 4 }}>
                  URL Mục tiêu: <span className="mono" style={{ color: 'var(--cyber-cyan)' }}>{scanResult.targetUrl}</span> • Thời gian quét: {scanResult.durationSeconds || 1}s
                </div>
              </div>

              {/* Grade Badge */}
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: 16,
                background: '#fff8f9',
                padding: '14px 20px',
                borderRadius: 10,
                border: '1px solid #fce7f3',
                boxShadow: '0 2px 8px rgba(236, 72, 153, 0.05)'
              }}>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 700 }}>
                    Xếp Hạng Bảo Mật
                  </div>
                  <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                    Điểm rủi ro: <strong>{scanResult.summary.riskScore}/100</strong>
                  </div>
                </div>

                <div style={{
                  width: 50,
                  height: 50,
                  borderRadius: 10,
                  background: `${getGradeColor(scanResult.summary.grade)}20`,
                  border: `2px solid ${getGradeColor(scanResult.summary.grade)}`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: 22,
                  fontWeight: 900,
                  color: getGradeColor(scanResult.summary.grade)
                }}>
                  {scanResult.summary.grade}
                </div>
              </div>
            </div>

            {/* Metrics Grid */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
              gap: 12,
              marginTop: 20
            }}>
              <div style={{ background: 'var(--bg-primary)', padding: '12px 14px', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>Tổng Cảnh Báo</div>
                <div style={{ fontSize: 18, fontWeight: 800, marginTop: 2 }}>{scanResult.summary.totalAlerts}</div>
              </div>

              <div style={{ background: 'var(--bg-primary)', padding: '12px 14px', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: 11, color: '#f87171' }}>Nguy Hiểm Cao (High)</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: '#f87171', marginTop: 2 }}>{scanResult.summary.highRiskCount}</div>
              </div>

              <div style={{ background: 'var(--bg-primary)', padding: '12px 14px', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: 11, color: '#fbbf24' }}>Trung Bình (Medium)</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: '#fbbf24', marginTop: 2 }}>{scanResult.summary.mediumRiskCount}</div>
              </div>

              <div style={{ background: 'var(--bg-primary)', padding: '12px 14px', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: 11, color: '#60a5fa' }}>Thấp (Low)</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: '#60a5fa', marginTop: 2 }}>{scanResult.summary.lowRiskCount}</div>
              </div>
            </div>
          </div>

          {/* Alert Findings List */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <h3 style={{ fontSize: 17, fontWeight: 700 }}>
              Chi Tiết Các Lỗ Hổng & Điểm Yếu Phát Hiện Được ({scanResult.alerts.length})
            </h3>

            {scanResult.alerts.map((alert, idx) => (
              <div
                key={idx}
                className="glass-card"
                style={{
                  padding: 20,
                  borderLeft: `4px solid ${alert.risk === 'High' ? '#ef4444' : alert.risk === 'Medium' ? '#f59e0b' : '#3b82f6'
                    }`
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 10 }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontSize: 16, fontWeight: 700 }}>{alert.name}</span>
                      {alert.cweId && (
                        <span className="badge badge-low mono">{alert.cweId}</span>
                      )}
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 4 }}>
                      Phương thức: <strong className="mono">{alert.method}</strong> • Tham số/Vị trí: <span className="mono" style={{ color: 'var(--text-muted)' }}>{alert.parameter || 'Global'}</span>
                    </div>
                  </div>

                  <div>
                    {getRiskBadge(alert.risk)}
                  </div>
                </div>

                {/* Description */}
                <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 10, lineHeight: 1.5 }}>
                  {alert.description}
                </div>

                {/* Evidence */}
                {alert.evidence && (
                  <div style={{
                    marginTop: 10,
                    padding: '8px 12px',
                    borderRadius: 6,
                    background: 'var(--bg-primary)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: 12,
                    color: '#38bdf8',
                    border: '1px solid var(--border-subtle)'
                  }}>
                    <strong>Dấu vết phát hiện:</strong> {alert.evidence}
                  </div>
                )}

                {/* Remediation Solution */}
                <div style={{
                  marginTop: 12,
                  padding: '10px 14px',
                  borderRadius: 6,
                  background: 'rgba(16, 185, 129, 0.08)',
                  borderLeft: '3px solid #10b981',
                  fontSize: 13,
                  color: 'var(--text-main)'
                }}>
                  <div style={{ fontWeight: 700, color: '#34d399', display: 'flex', alignItems: 'center', gap: 5 }}>
                    <Wrench size={13} />
                    <span>Phương Án Khắc Phục (Remediation):</span>
                  </div>
                  <div style={{ marginTop: 4, color: 'var(--text-muted)' }}>
                    {alert.solution}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

import React, { useState, useRef } from 'react';
import { UploadCloud, FileCode, CheckCircle2, AlertTriangle, ShieldCheck, Play, ArrowRight, FileArchive, RefreshCw } from 'lucide-react';
import { scanAPI } from '../services/api';

export default function Scanner({ onScanSuccess, stats }) {
  const [activeMode, setActiveMode] = useState('upload'); // 'upload' | 'paste'
  const [file, setFile] = useState(null);
  const [projectName, setProjectName] = useState('');
  const [pasteContent, setPasteContent] = useState('');
  const [pasteEcosystem, setPasteEcosystem] = useState('npm');
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [errorMessage, setErrorMessage] = useState('');
  const fileInputRef = useRef(null);

  const scanStepsText = [
    'Đang khởi tạo phiên phân tích bảo mật...',
    'Đang bóc tách danh sách thư viện phụ thuộc (Dependencies)...',
    'Đang truy vấn cơ sở dữ liệu OSV (Google Open Source Vulnerabilities)...',
    'Đang đối chiếu chéo với 1,700+ lỗ hổng CISA KEV (Chính phủ Hoa Kỳ)...',
    'Đang tính toán điểm số rủi ro CVSS và tổng hợp phiên bản vá...'
  ];

  const handleFileChange = (e) => {
    const selected = e.target.files[0];
    if (selected) {
      setFile(selected);
      if (!projectName) {
        setProjectName(selected.name.replace(/\.[^/.]+$/, ''));
      }
      setErrorMessage('');
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const dropped = e.dataTransfer.files[0];
      setFile(dropped);
      if (!projectName) {
        setProjectName(dropped.name.replace(/\.[^/.]+$/, ''));
      }
      setErrorMessage('');
    }
  };

  const handleDemoClick = () => {
    setActiveMode('paste');
    setPasteEcosystem('npm');
    setProjectName('Demo E-Commerce Service');
    setPasteContent(JSON.stringify({
      "name": "demo-vulnerable-service",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "4.17.15",
        "axios": "0.21.1",
        "express": "4.16.0",
        "jsonwebtoken": "8.5.1"
      }
    }, null, 2));
    setErrorMessage('');
  };

  const runScan = async () => {
    setErrorMessage('');
    setIsScanning(true);
    setScanStep(0);

    // Hiệu ứng chuyển bước quét trực quan
    const stepInterval = setInterval(() => {
      setScanStep((prev) => (prev < scanStepsText.length - 1 ? prev + 1 : prev));
    }, 700);

    try {
      let res;
      if (activeMode === 'upload') {
        if (!file) {
          throw new Error('Vui lòng chọn tệp package.json, requirements.txt hoặc .zip để quét');
        }
        const formData = new FormData();
        formData.append('file', file);
        formData.append('projectName', projectName || file.name);
        res = await scanAPI.uploadFile(formData);
      } else {
        if (!pasteContent.trim()) {
          throw new Error('Vui lòng dán nội dung manifest cần kiểm thử');
        }
        res = await scanAPI.scanRaw({
          projectName: projectName || 'Raw Snippet Scan',
          ecosystem: pasteEcosystem,
          content: pasteContent
        });
      }

      clearInterval(stepInterval);
      setIsScanning(false);
      onScanSuccess(res.data);
    } catch (err) {
      clearInterval(stepInterval);
      setIsScanning(false);
      setErrorMessage(err.response?.data?.error || err.message || 'Lỗi quét');
    }
  };

  return (
    <div style={{ maxWidth: 900, margin: '0 auto', padding: '40px 20px' }}>
      {/* Hero Title */}
      <div style={{ textAlign: 'center', marginBottom: 35 }}>
        <div style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
          background: '#fdf2f8',
          border: '1px solid #fbcfe8',
          color: '#db2777',
          padding: '4px 12px',
          borderRadius: 20,
          fontSize: 12,
          fontWeight: 700,
          marginBottom: 16
        }}>
          <ShieldCheck size={14} /> DevSecOps Supply Chain Security Engine
        </div>
        <h1 style={{
          fontSize: 34,
          fontWeight: 900,
          letterSpacing: '-0.02em',
          marginBottom: 12,
          lineHeight: 1.2,
          fontFamily: 'var(--font-heading)'
        }}>
          Kiểm Thử Lỗ Hổng Chuỗi Cung Ứng & Cảnh Báo <span style={{
            background: 'linear-gradient(135deg, #f43f5e, #db2777)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent'
          }}>CISA KEV</span>
        </h1>
        <p style={{ color: 'var(--text-muted)', fontSize: 15, maxWidth: 650, margin: '0 auto' }}>
          Tải lên dự án của bạn để phân tích toàn bộ thư viện bên thứ ba, phát hiện các mã độc, lỗ hổng CVE và các mối đe dọa đang bị khai thác thực tế trên toàn cầu.
        </p>

        {/* Global Stats Pill */}
        {stats && (
          <div style={{
            display: 'flex',
            justifyContent: 'center',
            gap: 24,
            marginTop: 20,
            fontSize: 13,
            color: 'var(--text-dim)'
          }}>
            <div>Tổng lượt quét: <strong style={{ color: 'var(--text-main)' }}>{stats.totalScans}</strong></div>
            <div>•</div>
            <div>Thư viện đã phân tích: <strong style={{ color: 'var(--text-main)' }}>{stats.totalPackagesScanned}</strong></div>
            <div>•</div>
            <div>Kho dữ liệu CISA KEV: <strong style={{ color: '#f87171' }}>1,700+ CVEs</strong></div>
          </div>
        )}
      </div>

      {/* Main Scanner Box */}
      <div className="glass-card" style={{ padding: 28, position: 'relative' }}>
        {/* Mode Selector Tabs */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          borderBottom: '1px solid var(--border-subtle)',
          paddingBottom: 16,
          marginBottom: 24
        }}>
          <div style={{ display: 'flex', gap: 10 }}>
            <button
              onClick={() => setActiveMode('upload')}
              style={{
                background: activeMode === 'upload' ? '#fdf2f8' : 'transparent',
                color: activeMode === 'upload' ? '#db2777' : 'var(--text-muted)',
                border: activeMode === 'upload' ? '1px solid #f472b6' : '1px solid transparent',
                padding: '8px 16px',
                borderRadius: 8,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                fontSize: 14,
                fontWeight: 700,
                fontFamily: 'var(--font-heading)',
                transition: 'all 0.2s'
              }}
            >
              <UploadCloud size={16} />
              <span>Tải Tệp Lên (File / Zip)</span>
            </button>

            <button
              onClick={() => setActiveMode('paste')}
              style={{
                background: activeMode === 'paste' ? '#fdf2f8' : 'transparent',
                color: activeMode === 'paste' ? '#db2777' : 'var(--text-muted)',
                border: activeMode === 'paste' ? '1px solid #f472b6' : '1px solid transparent',
                padding: '8px 16px',
                borderRadius: 8,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                fontSize: 14,
                fontWeight: 700,
                fontFamily: 'var(--font-heading)',
                transition: 'all 0.2s'
              }}
            >
              <FileCode size={16} />
              <span>Dán Nội Dung Manifest</span>
            </button>
          </div>

          <button
            onClick={handleDemoClick}
            style={{
              background: 'rgba(245, 158, 11, 0.1)',
              color: '#fbbf24',
              border: '1px solid rgba(245, 158, 11, 0.3)',
              padding: '6px 12px',
              borderRadius: 6,
              cursor: 'pointer',
              fontSize: 12,
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: 6
            }}
          >
            <Play size={13} />
            <span>Thử Mẫu Demo Lỗi</span>
          </button>
        </div>

        {/* Project Name Input */}
        <div style={{ marginBottom: 20 }}>
          <label style={{ display: 'block', fontSize: 13, color: 'var(--text-muted)', marginBottom: 6, fontWeight: 500 }}>
            Tên dự án (Project Name)
          </label>
          <input
            type="text"
            value={projectName}
            onChange={(e) => setProjectName(e.target.value)}
            placeholder="Ví dụ: Backend Microservice, Payment Gateway..."
            style={{
              width: '100%',
              background: 'var(--bg-primary)',
              border: '1px solid var(--border-subtle)',
              padding: '10px 14px',
              borderRadius: 8,
              color: 'var(--text-main)',
              fontSize: 14,
              outline: 'none'
            }}
          />
        </div>

        {/* Mode 1: File Upload */}
        {activeMode === 'upload' && (
          <div>
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              style={{
                border: '2px dashed ' + (file ? '#10b981' : '#f472b6'),
                borderRadius: 12,
                padding: '40px 20px',
                textAlign: 'center',
                cursor: 'pointer',
                background: file ? '#ecfdf5' : '#fff5f7',
                transition: 'all 0.2s'
              }}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".json,.txt,.zip"
                style={{ display: 'none' }}
                onChange={handleFileChange}
              />
              {file ? (
                <div>
                  <div style={{ display: 'inline-flex', padding: 12, borderRadius: 50, background: '#d1fae5', color: '#059669', marginBottom: 12 }}>
                    <CheckCircle2 size={32} />
                  </div>
                  <div style={{ fontSize: 16, fontWeight: 700, color: '#111827' }}>{file.name}</div>
                  <div style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>
                    {(file.size / 1024).toFixed(1)} KB • Nhấn để chọn file khác
                  </div>
                </div>
              ) : (
                <div>
                  <div style={{ display: 'inline-flex', padding: 14, borderRadius: 50, background: '#fce7f3', color: '#db2777', marginBottom: 12 }}>
                    <UploadCloud size={36} />
                  </div>
                  <div style={{ fontSize: 16, fontWeight: 700, color: '#111827' }}>Kéo & thả file dự án vào đây, hoặc click để chọn</div>
                  <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 6 }}>
                    Hỗ trợ <code style={{ color: '#db2777', fontWeight: 600 }}>package.json</code> (Node.js), <code style={{ color: '#db2777', fontWeight: 600 }}>requirements.txt</code> (Python), hoặc file nén <code style={{ color: '#db2777', fontWeight: 600 }}>.zip</code>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Mode 2: Paste Manifest */}
        {activeMode === 'paste' && (
          <div>
            <div style={{ display: 'flex', gap: 12, marginBottom: 12, alignItems: 'center' }}>
              <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>Hệ sinh thái:</span>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, cursor: 'pointer' }}>
                <input
                  type="radio"
                  name="ecosystem"
                  value="npm"
                  checked={pasteEcosystem === 'npm'}
                  onChange={() => setPasteEcosystem('npm')}
                />
                Node.js (npm / package.json)
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, cursor: 'pointer' }}>
                <input
                  type="radio"
                  name="ecosystem"
                  value="pypi"
                  checked={pasteEcosystem === 'pypi'}
                  onChange={() => setPasteEcosystem('pypi')}
                />
                Python (PyPI / requirements.txt)
              </label>
            </div>
            <textarea
              rows={8}
              value={pasteContent}
              onChange={(e) => setPasteContent(e.target.value)}
              placeholder={
                pasteEcosystem === 'npm'
                  ? '{\n  "dependencies": {\n    "lodash": "4.17.15",\n    "axios": "0.21.1"\n  }\n}'
                  : 'lodash==4.17.15\nrequests==2.20.0\njinja2==2.11.2'
              }
              style={{
                width: '100%',
                background: 'var(--bg-primary)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 8,
                padding: '12px 14px',
                color: 'var(--text-main)',
                fontFamily: 'var(--font-mono)',
                fontSize: 13,
                outline: 'none',
                resize: 'vertical'
              }}
            />
          </div>
        )}

        {/* Error Alert */}
        {errorMessage && (
          <div style={{
            marginTop: 16,
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

        {/* Scanning Progress Overlay */}
        {isScanning ? (
          <div style={{ marginTop: 24, textAlign: 'center', padding: '20px 0' }} className="radar-scanner">
            <RefreshCw size={36} color="var(--cyber-cyan)" style={{ animation: 'spin 1.5s linear infinite', margin: '0 auto 14px' }} />
            <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--cyber-cyan)' }}>
              {scanStepsText[scanStep]}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 6 }}>
              Vui lòng đợi giây lát, hệ thống đang đối chiếu cơ sở dữ liệu quốc tế...
            </div>
            <style>{`@keyframes spin { 100% { transform: rotate(360deg); } }`}</style>
          </div>
        ) : (
          <div style={{ marginTop: 24, display: 'flex', justifyContent: 'flex-end' }}>
            <button
              onClick={runScan}
              className="btn-primary"
              style={{ padding: '12px 28px', fontSize: 15 }}
            >
              <span>Bắt Đầu Quét Bảo Mật</span>
              <ArrowRight size={18} />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

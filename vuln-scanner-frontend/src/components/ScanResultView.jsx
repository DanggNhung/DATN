import React, { useState } from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, ArrowLeft, Download, 
  ExternalLink, ChevronDown, ChevronUp, Search, Filter, CheckCircle, 
  Flame, Wrench, FileText, Printer, Bug
} from 'lucide-react';
import AuditReportModal from './AuditReportModal';
import { exportWordReport } from '../utils/exportWordReport';

function decodeUtf8Safe(str) {
  if (!str) return '';
  try {
    if (/[ÄÅá»º·]/.test(str)) {
      return decodeURIComponent(escape(str));
    }
  } catch (e) {}
  return str;
}

export default function ScanResultView({ scanData, onBack }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('all'); // 'all' | 'vulnerable' | 'cisa' | 'safe'
  const [expandedPkg, setExpandedPkg] = useState(null);
  const [isAuditModalOpen, setIsAuditModalOpen] = useState(false);
  const [isExportingWord, setIsExportingWord] = useState(false);

  if (!scanData) return null;

  const { summary = {}, results = [], projectName, fileName, fileType, scannedAt } = scanData;
  const displayProjectName = decodeUtf8Safe(projectName) || 'Dự án phân tích';
  const displayFileName = decodeUtf8Safe(fileName) || 'manifest.json';
  const displayFileType = (fileType || 'npm').toUpperCase();

  // Lọc danh sách packages
  const filteredResults = (results || []).filter((pkg) => {
    const matchesSearch = pkg.package.toLowerCase().includes(searchTerm.toLowerCase()) ||
      pkg.vulnerabilities?.some((v) => v.id.toLowerCase().includes(searchTerm.toLowerCase()));

    if (!matchesSearch) return false;

    if (filterType === 'vulnerable') return pkg.isVulnerable;
    if (filterType === 'cisa') return pkg.hasCisaKev;
    if (filterType === 'safe') return !pkg.isVulnerable;
    return true;
  });

  // Tải báo cáo dạng Word (.docx)
  const handleExportWord = async () => {
    setIsExportingWord(true);
    await exportWordReport(scanData);
    setIsExportingWord(false);
  };

  // Tải báo cáo dạng JSON
  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(scanData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `secshield_report_${projectName || 'scan'}_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getRiskColor = (level) => {
    switch (level) {
      case 'CRITICAL': return '#ef4444';
      case 'HIGH': return '#f59e0b';
      case 'MEDIUM': return '#3b82f6';
      case 'LOW': return '#94a3b8';
      default: return '#10b981';
    }
  };

  const riskColor = getRiskColor(summary.riskLevel);

  return (
    <div style={{ maxWidth: 1050, margin: '0 auto', padding: '30px 20px' }}>
      {/* Top Bar with Back and Export */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <button onClick={onBack} className="btn-secondary" style={{ padding: '8px 14px', fontSize: 13 }}>
          <ArrowLeft size={16} />
          <span>Quay Lại Quét Tệp Khác</span>
        </button>

        <div style={{ display: 'flex', gap: 10 }}>
          <button 
            onClick={handleExportWord} 
            disabled={isExportingWord}
            className="btn-primary" 
            style={{
              padding: '8px 16px',
              fontSize: 13,
              background: 'linear-gradient(135deg, #2563eb, #1d4ed8)',
              boxShadow: '0 0 15px rgba(37, 99, 235, 0.3)',
              border: 'none',
              cursor: isExportingWord ? 'wait' : 'pointer'
            }}
          >
            <FileText size={15} />
            <span>{isExportingWord ? 'Đang tạo file Word...' : 'Xuất Báo Cáo Word (.docx)'}</span>
          </button>

          <button 
            onClick={() => setIsAuditModalOpen(true)} 
            className="btn-secondary" 
            style={{ padding: '8px 14px', fontSize: 13 }}
          >
            <Printer size={15} />
            <span>Xem Trước / In Báo Cáo</span>
          </button>

          <button onClick={handleExportJson} className="btn-secondary" style={{ padding: '8px 14px', fontSize: 13 }}>
            <Download size={15} />
            <span>Xuất JSON</span>
          </button>
        </div>
      </div>

      {/* Main Risk Overview Card (VirusTotal style) */}
      <div className="glass-card" style={{ padding: 28, marginBottom: 24, borderTop: `4px solid ${riskColor}` }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 20 }}>
          <div>
            <div style={{ fontSize: 12, color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.05em' }}>
              Báo Cáo An Toàn Phần Mềm
            </div>
            <h2 style={{ fontSize: 24, fontWeight: 800, marginTop: 4, display: 'flex', alignItems: 'center', gap: 10 }}>
              <span>{displayProjectName || displayFileName}</span>
              <span style={{ fontSize: 12, padding: '2px 8px', borderRadius: 4, background: 'rgba(255,255,255,0.06)', color: 'var(--text-muted)' }}>
                {displayFileType}
              </span>
            </h2>
            <div style={{ fontSize: 13, color: 'var(--text-dim)', marginTop: 4 }}>
              Tệp quét: <span className="mono" style={{ color: 'var(--text-muted)' }}>{displayFileName}</span> • Ngày quét: {scannedAt ? new Date(scannedAt).toLocaleString('vi-VN') : 'Vừa xong'}
            </div>
          </div>

          {/* VirusTotal Risk Gauge */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 16,
            background: '#fff8f9',
            padding: '16px 24px',
            borderRadius: 12,
            border: `1px solid ${riskColor}40`,
            boxShadow: '0 2px 8px rgba(236, 72, 153, 0.05)'
          }}>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: 11, color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 700 }}>
                Cấp Độ Rủi Ro
              </div>
              <div style={{ fontSize: 20, fontWeight: 800, color: riskColor }}>
                {summary.riskLevel}
              </div>
            </div>
            <div style={{
              width: 60,
              height: 60,
              borderRadius: '50%',
              border: `4px solid ${riskColor}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 18,
              fontWeight: 800,
              color: riskColor,
              boxShadow: `0 0 15px ${riskColor}40`
            }}>
              {summary.riskScore}
            </div>
          </div>
        </div>

        {/* Special CISA Alert Banner if CISA KEV detected */}
        {summary.cisaKevCount > 0 && (
          <div style={{
            marginTop: 20,
            padding: '14px 18px',
            borderRadius: 8,
            background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.2), rgba(139, 92, 246, 0.15))',
            border: '1px solid rgba(239, 68, 68, 0.5)',
            display: 'flex',
            alignItems: 'center',
            gap: 12
          }}>
            <Flame size={24} color="#f87171" style={{ flexShrink: 0 }} />
            <div>
              <strong style={{ color: '#f87171', fontSize: 14 }}>
                CẢNH BÁO NGUY HIỂM: Phát hiện {summary.cisaKevCount} lỗ hổng thuộc danh mục CISA KEV!
              </strong>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                Các lỗ hổng này được Cơ quan An ninh mạng Hoa Kỳ (CISA) xác nhận đang bị hacker chủ động khai thác thực tế trên Internet. Cần vá ngay lập tức!
              </div>
            </div>
          </div>
        )}

        {/* Summary Stats Grid */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: 14,
          marginTop: 22
        }}>
          <div style={{ background: 'var(--bg-primary)', padding: '14px 16px', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: 12, color: 'var(--text-dim)' }}>Tổng số thư viện</div>
            <div style={{ fontSize: 22, fontWeight: 800, marginTop: 4 }}>{summary.totalPackages}</div>
          </div>

          <div style={{ background: 'var(--bg-primary)', padding: '14px 16px', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: 12, color: '#f87171' }}>Thư viện dính lỗ hổng</div>
            <div style={{ fontSize: 22, fontWeight: 800, color: '#f87171', marginTop: 4 }}>{summary.vulnerablePackages}</div>
          </div>

          <div style={{ background: 'var(--bg-primary)', padding: '14px 16px', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: 12, color: '#34d399' }}>Thư viện an toàn</div>
            <div style={{ fontSize: 22, fontWeight: 800, color: '#34d399', marginTop: 4 }}>{summary.safePackages}</div>
          </div>

          <div style={{ background: 'var(--bg-primary)', padding: '14px 16px', borderRadius: 8, border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: 12, color: 'var(--cyber-purple)' }}>Cảnh báo CISA KEV</div>
            <div style={{ fontSize: 22, fontWeight: 800, color: 'var(--cyber-purple)', marginTop: 4 }}>{summary.cisaKevCount}</div>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: 14,
        marginBottom: 18
      }}>
        {/* Search */}
        <div style={{ position: 'relative', width: 300 }}>
          <Search size={16} color="var(--text-dim)" style={{ position: 'absolute', left: 12, top: 11 }} />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Tìm theo tên thư viện hoặc mã CVE..."
            style={{
              width: '100%',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border-subtle)',
              padding: '8px 12px 8px 36px',
              borderRadius: 8,
              color: 'var(--text-main)',
              fontSize: 13,
              outline: 'none'
            }}
          />
        </div>

        {/* Filter Pills */}
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={() => setFilterType('all')}
            style={{
              background: filterType === 'all' ? 'var(--bg-tertiary)' : 'transparent',
              color: filterType === 'all' ? 'var(--cyber-cyan)' : 'var(--text-dim)',
              border: filterType === 'all' ? '1px solid rgba(6, 182, 212, 0.4)' : '1px solid var(--border-subtle)',
              padding: '6px 12px',
              borderRadius: 6,
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            Tất cả ({results.length})
          </button>

          <button
            onClick={() => setFilterType('vulnerable')}
            style={{
              background: filterType === 'vulnerable' ? 'rgba(239, 68, 68, 0.15)' : 'transparent',
              color: filterType === 'vulnerable' ? '#f87171' : 'var(--text-dim)',
              border: filterType === 'vulnerable' ? '1px solid rgba(239, 68, 68, 0.4)' : '1px solid var(--border-subtle)',
              padding: '6px 12px',
              borderRadius: 6,
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            Có lỗ hổng ({summary.vulnerablePackages})
          </button>

          {summary.cisaKevCount > 0 && (
            <button
              onClick={() => setFilterType('cisa')}
              style={{
                background: filterType === 'cisa' ? 'rgba(139, 92, 246, 0.2)' : 'transparent',
                color: filterType === 'cisa' ? '#c084fc' : 'var(--text-dim)',
                border: filterType === 'cisa' ? '1px solid rgba(139, 92, 246, 0.4)' : '1px solid var(--border-subtle)',
                padding: '6px 12px',
                borderRadius: 6,
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              CISA KEV ({summary.cisaKevCount})
            </button>
          )}

          <button
            onClick={() => setFilterType('safe')}
            style={{
              background: filterType === 'safe' ? 'rgba(16, 185, 129, 0.15)' : 'transparent',
              color: filterType === 'safe' ? '#34d399' : 'var(--text-dim)',
              border: filterType === 'safe' ? '1px solid rgba(16, 185, 129, 0.4)' : '1px solid var(--border-subtle)',
              padding: '6px 12px',
              borderRadius: 6,
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            An toàn ({summary.safePackages})
          </button>
        </div>
      </div>

      {/* Package Results List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {filteredResults.map((pkg, idx) => {
          const isExpanded = expandedPkg === idx;

          return (
            <div key={idx} className="glass-card" style={{ padding: 18, borderLeft: pkg.isVulnerable ? '4px solid #ef4444' : '4px solid #10b981' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <div style={{
                    width: 36,
                    height: 36,
                    borderRadius: 8,
                    background: pkg.isVulnerable ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                    color: pkg.isVulnerable ? '#f87171' : '#34d399',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}>
                    {pkg.isVulnerable ? <AlertTriangle size={18} /> : <CheckCircle size={18} />}
                  </div>

                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontSize: 16, fontWeight: 700 }} className="mono">{pkg.package}</span>
                      <span className="badge badge-low mono">v{pkg.version}</span>
                      <span className="badge" style={{ background: 'rgba(255,255,255,0.06)', color: 'var(--text-dim)' }}>
                        {pkg.ecosystem}
                      </span>
                    </div>

                    {/* Remediation Suggestion */}
                    {pkg.isVulnerable && pkg.fixedVersion && (
                      <div style={{ fontSize: 12, color: '#38bdf8', marginTop: 4, display: 'flex', alignItems: 'center', gap: 5 }}>
                        <Wrench size={13} />
                        <span><strong>Khắc phục:</strong> Nâng cấp lên phiên bản <code className="mono" style={{ background: 'rgba(56, 189, 248, 0.15)', padding: '1px 5px', borderRadius: 4 }}>{pkg.fixedVersion}</code></span>
                      </div>
                    )}
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  {pkg.hasCisaKev && (
                    <span className="badge badge-cisa">
                      <Flame size={12} /> CISA KEV
                    </span>
                  )}

                  {pkg.hasExploitDb && (
                    <span className="badge badge-exploitdb">
                      <Bug size={12} /> Exploit-DB PoC
                    </span>
                  )}

                  {pkg.isVulnerable ? (
                    <span className="badge badge-critical">
                      {pkg.totalVulnerabilities} lỗ hổng CVE
                    </span>
                  ) : (
                    <span className="badge badge-safe">
                      An toàn
                    </span>
                  )}

                  {pkg.isVulnerable && (
                    <button
                      onClick={() => setExpandedPkg(isExpanded ? null : idx)}
                      className="btn-secondary"
                      style={{ padding: '6px 10px', fontSize: 12 }}
                    >
                      {isExpanded ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
                      <span>{isExpanded ? 'Thu gọn' : 'Xem chi tiết'}</span>
                    </button>
                  )}
                </div>
              </div>

              {/* Expanded Vulnerabilities List */}
              {isExpanded && pkg.vulnerabilities && (
                <div style={{ marginTop: 18, borderTop: '1px solid var(--border-subtle)', paddingTop: 14 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 10 }}>
                    Danh sách chi tiết {pkg.vulnerabilities.length} lỗ hổng đã được xác nhận:
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    {pkg.vulnerabilities.map((v, vIdx) => (
                      <div
                        key={vIdx}
                        style={{
                          background: 'var(--bg-primary)',
                          borderRadius: 8,
                          padding: 14,
                          border: v.isCisaKev ? '1px solid rgba(239, 68, 68, 0.5)' : '1px solid var(--border-subtle)'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 8 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span className="mono" style={{ fontWeight: 700, color: '#38bdf8' }}>{v.id}</span>
                            {v.aliases && v.aliases.length > 0 && (
                              <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>
                                ({v.aliases.join(', ')})
                              </span>
                            )}
                            {v.isCisaKev && (
                              <span className="badge badge-cisa">
                                <Flame size={12} /> CISA KEV (Active Exploit)
                              </span>
                            )}
                            {v.hasExploitDb && (
                              <span className="badge badge-exploitdb">
                                <Bug size={12} /> Exploit-DB PoC
                              </span>
                            )}
                          </div>

                          <span className={`badge badge-${v.severity.toLowerCase()}`}>
                            {v.severity}
                          </span>
                        </div>

                        {/* Summary / Description */}
                        <div style={{ fontSize: 13, color: 'var(--text-main)', marginTop: 8, lineHeight: 1.5 }}>
                          {v.summary}
                        </div>

                        {/* Exploit-DB Details if any */}
                        {v.hasExploitDb && v.exploitDbList && v.exploitDbList.length > 0 && (
                          <div style={{
                            marginTop: 10,
                            padding: '10px 12px',
                            borderRadius: 6,
                            background: 'rgba(249, 115, 22, 0.08)',
                            borderLeft: '3px solid #f97316',
                            fontSize: 12
                          }}>
                            <div style={{ fontWeight: 700, color: '#fb923c', display: 'flex', alignItems: 'center', gap: 6 }}>
                              <Bug size={14} /> Có Mã Khai Thác Trên Exploit-DB (Public PoC)
                            </div>
                            <div style={{ marginTop: 6, display: 'flex', flexDirection: 'column', gap: 6 }}>
                              {v.exploitDbList.slice(0, 3).map((exp, expIdx) => (
                                <div key={expIdx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                                  <div style={{ color: 'var(--text-main)' }}>
                                    <strong className="mono" style={{ color: '#fdba74' }}>[EDB-{exp.edbId}]</strong> {exp.description}
                                  </div>
                                  <a
                                    href={exp.url}
                                    target="_blank"
                                    rel="noreferrer"
                                    style={{ color: '#38bdf8', textDecoration: 'underline', fontSize: 11, display: 'flex', alignItems: 'center', gap: 3 }}
                                  >
                                    <span>Xem PoC</span>
                                    <ExternalLink size={11} />
                                  </a>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* CISA Details if any */}
                        {v.isCisaKev && v.cisaKevDetails && (
                          <div style={{
                            marginTop: 10,
                            padding: '10px 12px',
                            borderRadius: 6,
                            background: 'rgba(239, 68, 68, 0.08)',
                            borderLeft: '3px solid #ef4444',
                            fontSize: 12
                          }}>
                            <div style={{ fontWeight: 700, color: '#f87171' }}>
                              CISA KEV - {v.cisaKevDetails.vulnerabilityName}
                            </div>
                            <div style={{ color: 'var(--text-muted)', marginTop: 3 }}>
                              <strong>Hành động yêu cầu:</strong> {v.cisaKevDetails.requiredAction}
                            </div>
                            <div style={{ color: 'var(--text-dim)', marginTop: 2 }}>
                              Chiến dịch Ransomware: {v.cisaKevDetails.knownRansomwareCampaignUse} • Ngày đưa vào catalog: {v.cisaKevDetails.dateAdded}
                            </div>
                          </div>
                        )}

                        {/* References */}
                        {v.references && v.references.length > 0 && (
                          <div style={{ marginTop: 10, display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                            {v.references.slice(0, 3).map((refUrl, rIdx) => (
                              <a
                                key={rIdx}
                                href={refUrl}
                                target="_blank"
                                rel="noreferrer"
                                style={{
                                  fontSize: 11,
                                  color: 'var(--cyber-cyan)',
                                  textDecoration: 'none',
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: 4
                                }}
                              >
                                <span>Tài liệu tham khảo</span>
                                <ExternalLink size={11} />
                              </a>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
      
      {/* Official Printable Audit Report Modal */}
      <AuditReportModal
        isOpen={isAuditModalOpen}
        onClose={() => setIsAuditModalOpen(false)}
        scanData={scanData}
      />
    </div>
  );
}

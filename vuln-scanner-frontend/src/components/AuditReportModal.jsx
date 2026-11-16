import React, { useState } from 'react';
import { Printer, Download, X, FileText, Flame } from 'lucide-react';
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

export default function AuditReportModal({ isOpen, onClose, scanData }) {
  const [isExporting, setIsExporting] = useState(false);

  if (!isOpen || !scanData) return null;

  const { summary = {}, results = [], projectName, fileName, fileType, scannedAt } = scanData;
  const displayProjectName = decodeUtf8Safe(projectName) || 'Dự án phân tích';
  const displayFileName = decodeUtf8Safe(fileName) || 'manifest.json';
  const displayFileType = (fileType || 'npm').toUpperCase();

  const vulnerablePackages = results.filter((p) => p.isVulnerable);
  const totalVulnsCount = vulnerablePackages.reduce((acc, p) => acc + (p.vulnerabilities?.length || 0), 0);
  
  // AUD-02: Kiểm tra lỗ hổng chưa xác định severity (UNKNOWN)
  const unknownVulnsCount = vulnerablePackages.reduce((acc, p) => {
    return acc + (p.vulnerabilities || []).filter((v) => (v.severity || '').toUpperCase().trim() === 'UNKNOWN').length;
  }, 0);
  const hasUnknownVulns = summary.hasUnknownSeverity || summary.unknownCount > 0 || (unknownVulnsCount > 0 && vulnerablePackages.length > 0);

  const getRiskColor = (level) => {
    switch (level) {
      case 'CRITICAL': return '#dc2626';
      case 'HIGH': return '#d97706';
      case 'MEDIUM': return '#2563eb';
      case 'LOW': return '#4b5563';
      case 'INCONCLUSIVE': return '#ea580c';
      default: return '#059669';
    }
  };

  const riskColor = getRiskColor(summary.riskLevel);

  const handleDownloadWord = async () => {
    setIsExporting(true);
    await exportWordReport(scanData);
    setIsExporting(false);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="modal-overlay" style={{ overflowY: 'auto', padding: '20px 10px', alignItems: 'flex-start' }}>
      {/* Top Action Bar (hidden in print) */}
      <div className="no-print" style={{
        position: 'sticky',
        top: 10,
        zIndex: 1100,
        maxWidth: 860,
        width: '100%',
        margin: '0 auto 16px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: 12,
        background: '#1e293b',
        padding: '12px 20px',
        borderRadius: 10,
        border: '1px solid rgba(255,255,255,0.1)',
        boxShadow: '0 10px 25px rgba(0,0,0,0.5)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <FileText size={20} color="#38bdf8" />
          <span style={{ fontWeight: 700, fontSize: 15, color: '#f8fafc' }}>
            Xem Trước Báo Cáo Lỗ Hổng Bảo Mật
          </span>
        </div>

        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <button
            onClick={handleDownloadWord}
            disabled={isExporting}
            className="btn-primary"
            style={{ padding: '8px 18px', fontSize: 13, background: 'linear-gradient(135deg, #2563eb, #1d4ed8)', border: 'none' }}
          >
            <Download size={16} />
            <span>{isExporting ? 'Đang tạo file Word...' : 'Tải File Word (.docx)'}</span>
          </button>

          <button
            onClick={handlePrint}
            className="btn-secondary"
            style={{ padding: '8px 14px', fontSize: 13 }}
          >
            <Printer size={16} />
            <span>In Bản Giấy / PDF</span>
          </button>

          <button
            onClick={onClose}
            className="btn-secondary"
            style={{ padding: '8px 14px', fontSize: 13 }}
          >
            <X size={16} />
            <span>Đóng</span>
          </button>
        </div>
      </div>

      {/* Printable Document Paper */}
      <div
        id="audit-report-document"
        style={{
          maxWidth: 860,
          width: '100%',
          margin: '0 auto',
          background: '#ffffff',
          color: '#1e293b',
          borderRadius: 8,
          padding: 'clamp(16px, 4vw, 48px)',
          boxShadow: '0 15px 40px rgba(0,0,0,0.6)',
          fontFamily: "'Times New Roman', Times, serif",
          fontSize: '15px',
          lineHeight: '1.5',
          position: 'relative'
        }}
      >
        {/* Report Title */}
        <div style={{ textAlign: 'center', marginBottom: 24 }}>
          <h1 style={{
            fontSize: 24,
            fontWeight: 800,
            color: '#0f172a',
            textTransform: 'uppercase',
            letterSpacing: '0.02em',
            margin: 0,
            fontFamily: "'Times New Roman', Times, serif"
          }}>
            BÁO CÁO TỔNG HỢP LỖ HỔNG BẢO MẬT
          </h1>
          <div style={{ fontSize: 14, color: '#475569', marginTop: 6, fontStyle: 'italic', fontFamily: "'Times New Roman', Times, serif" }}>
            Danh sách chi tiết các lỗ hổng mã nguồn mở và hướng dẫn khắc phục
          </div>
        </div>

        {/* Project Target & Overview Card */}
        <div style={{
          border: '1px solid #cbd5e1',
          borderRadius: 6,
          padding: '16px 20px',
          background: '#f8fafc',
          marginBottom: 20,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#475569', textTransform: 'uppercase' }}>
              Dự án kiểm thử
            </div>
            <div style={{ fontSize: 19, fontWeight: 800, color: '#0f172a', marginTop: 2 }}>
              {displayProjectName}
            </div>
            <div style={{ fontSize: 14, color: '#334155', marginTop: 4 }}>
              Tệp phân tích: <strong>{displayFileName}</strong> ({displayFileType}) • Ngày quét: {scannedAt ? new Date(scannedAt).toLocaleString('vi-VN') : new Date().toLocaleString('vi-VN')}
            </div>
          </div>

          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#475569', textTransform: 'uppercase' }}>
              Cấp Độ Rủi Ro
            </div>
            <div style={{ fontSize: 22, fontWeight: 900, color: riskColor }}>
              {summary.riskLevel || 'N/A'}
            </div>
            <div style={{ fontSize: 13, color: '#475569' }}>
              Điểm rủi ro: <strong>{summary.riskScore ?? 0}/100</strong>
            </div>
          </div>
        </div>

        {/* CISA KEV Alert Banner (if applicable) */}
        {summary.cisaKevCount > 0 && (
          <div style={{
            borderLeft: '4px solid #dc2626',
            background: '#fef2f2',
            padding: '12px 16px',
            borderRadius: 6,
            marginBottom: 20,
            display: 'flex',
            alignItems: 'center',
            gap: 12
          }}>
            <Flame size={22} color="#dc2626" style={{ flexShrink: 0 }} />
            <div>
              <strong style={{ color: '#b91c1c', fontSize: 14 }}>
                CẢNH BÁO MỨC ĐỘ NGUY HIỂM CAO (CISA KEV ALERT):
              </strong>
              <div style={{ fontSize: 13, color: '#7f1d1d', marginTop: 2 }}>
                Phát hiện {summary.cisaKevCount} lỗ hổng thuộc danh mục Known Exploited Vulnerabilities của CISA đang bị tin tặc chủ động khai thác thực tế. Cần ưu tiên nâng cấp ngay lập tức!
              </div>
            </div>
          </div>
        )}

        {/* AUD-02 Alert Banner for UNKNOWN severity */}
        {hasUnknownVulns && (
          <div style={{
            borderLeft: '4px solid #f97316',
            background: '#fff7ed',
            padding: '12px 16px',
            borderRadius: 6,
            marginBottom: 20,
            display: 'flex',
            alignItems: 'center',
            gap: 12
          }}>
            <AlertTriangle size={22} color="#ea580c" style={{ flexShrink: 0 }} />
            <div>
              <strong style={{ color: '#c2410c', fontSize: 14 }}>
                CẢNH BÁO DỮ LIỆU & HẠN CHẾ THANG ĐIỂM (AUD-02):
              </strong>
              <div style={{ fontSize: 13, color: '#9a3412', marginTop: 2 }}>
                Phát hiện {summary.unknownCount || unknownVulnsCount} lỗ hổng chưa được công bố đầy đủ điểm số CVSS/Severity (mức độ UNKNOWN). Hệ thống xếp loại rủi ro tổng thể là <strong>INCONCLUSIVE (Chưa đủ dữ liệu đánh giá)</strong> và <strong>tuyệt đối không kết luận an toàn (SAFE)</strong> nhằm tránh rủi ro tiềm ẩn cho chuỗi cung ứng phần mềm.
              </div>
            </div>
          </div>
        )}

        {/* Metric Cards Summary */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 12, marginBottom: 24 }}>
          <div style={{ border: '1px solid #cbd5e1', borderRadius: 6, padding: '10px 14px', textAlign: 'center', background: '#ffffff' }}>
            <div style={{ fontSize: 12, color: '#475569', fontWeight: 600 }}>Tổng Thư Viện Quét</div>
            <div style={{ fontSize: 20, fontWeight: 800, color: '#0f172a', marginTop: 2 }}>
              {summary.totalPackages ?? results.length}
            </div>
          </div>

          <div style={{ border: '1px solid #fca5a5', borderRadius: 6, padding: '10px 14px', textAlign: 'center', background: '#fff5f5' }}>
            <div style={{ fontSize: 12, color: '#b91c1c', fontWeight: 600 }}>Thư Viện Dính Lỗi</div>
            <div style={{ fontSize: 20, fontWeight: 800, color: '#dc2626', marginTop: 2 }}>
              {vulnerablePackages.length}
            </div>
          </div>

          <div style={{ border: '1px solid #fda4af', borderRadius: 6, padding: '10px 14px', textAlign: 'center', background: '#fff1f2' }}>
            <div style={{ fontSize: 12, color: '#e11d48', fontWeight: 600 }}>Tổng Số Lỗi (CVEs)</div>
            <div style={{ fontSize: 20, fontWeight: 800, color: '#e11d48', marginTop: 2 }}>
              {totalVulnsCount}
            </div>
          </div>

          <div style={{ border: '1px solid #86efac', borderRadius: 6, padding: '10px 14px', textAlign: 'center', background: '#f0fdf4' }}>
            <div style={{ fontSize: 12, color: '#15803d', fontWeight: 600 }}>Thư Viện An Toàn</div>
            <div style={{ fontSize: 20, fontWeight: 800, color: '#16a34a', marginTop: 2 }}>
              {summary.safePackages ?? results.filter((p) => p.isSafe).length}
            </div>
          </div>

          {hasUnknownVulns && (
            <div style={{ border: '1px solid #fed7aa', borderRadius: 6, padding: '10px 14px', textAlign: 'center', background: '#fff7ed' }}>
              <div style={{ fontSize: 12, color: '#c2410c', fontWeight: 600 }}>Lỗi Chưa Rõ Severity</div>
              <div style={{ fontSize: 20, fontWeight: 800, color: '#ea580c', marginTop: 2 }}>
                {summary.unknownCount || unknownVulnsCount}
              </div>
            </div>
          )}

          {(summary.errorPackages > 0 || results.some((p) => p.hasScanError)) && (
            <div style={{ border: '1px solid #fde68a', borderRadius: 6, padding: '10px 14px', textAlign: 'center', background: '#fefce8' }}>
              <div style={{ fontSize: 12, color: '#b45309', fontWeight: 600 }}>Lỗi Kiểm Tra OSV</div>
              <div style={{ fontSize: 20, fontWeight: 800, color: '#d97706', marginTop: 2 }}>
                {summary.errorPackages ?? results.filter((p) => p.hasScanError).length}
              </div>
            </div>
          )}
        </div>

        {/* Scoring Scale & Limitation Notice (AUD-02) */}
        <div style={{
          marginBottom: 24,
          padding: '12px 16px',
          background: '#f8fafc',
          border: '1px solid #cbd5e1',
          borderRadius: 6,
          fontSize: 12,
          lineHeight: 1.5,
          color: '#334155'
        }}>
          <strong style={{ color: '#0f172a' }}>📌 Ghi chú phương pháp & Hạn chế thang điểm đánh giá rủi ro (AUD-02):</strong>
          <div style={{ marginTop: 4 }}>
            Thang điểm rủi ro (0-100) phân cấp từ CRITICAL (85-100), HIGH (60-84), MEDIUM (30-59), LOW (10-29), SAFE (0 - An toàn tuyệt đối) đến INCONCLUSIVE (Chưa đủ dữ liệu). Hệ thống <strong>chỉ kết luận SAFE khi toàn bộ thư viện được xác minh thành công và không có lỗ hổng</strong>. Trường hợp phát hiện lỗ hổng nhưng severity là UNKNOWN, hệ thống phân loại <strong>INCONCLUSIVE</strong> và không dùng kết luận SAFE để đảm bảo tính an toàn nghiêm ngặt.
          </div>
        </div>

        {/* Section 1: Summary Table */}
        <div style={{ marginBottom: 30 }}>
          <h2 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', borderBottom: '1px solid #cbd5e1', paddingBottom: 6, marginBottom: 12, fontFamily: "'Times New Roman', Times, serif" }}>
            I. BẢNG TỔNG HỢP CÁC GÓI THƯ VIỆN CÓ LỖ HỔNG
          </h2>

          {vulnerablePackages.length === 0 ? (
            (summary.hasScanErrors || summary.errorPackages > 0 || results.some((p) => p.hasScanError)) ? (
              <div style={{ padding: '12px 16px', background: '#fffbeb', color: '#b45309', borderRadius: 6, fontSize: 13, border: '1px solid #fde68a' }}>
                ⚠️ <strong>Phạm vi dữ liệu:</strong> Quá trình kiểm tra ghi nhận {summary.errorPackages || results.filter((p) => p.hasScanError).length} gói thư viện gặp sự cố kết nối tới nguồn Google OSV. Trong phạm vi các gói đã truy vấn thành công ({summary.safePackages ?? results.filter((p) => p.isSafe).length} gói), không phát hiện lỗ hổng. Chưa thể kết luận an toàn tuyệt đối cho toàn bộ dự án.
              </div>
            ) : (
              <div style={{ padding: '12px 16px', background: '#f0fdf4', color: '#16a34a', borderRadius: 6, fontSize: 14, fontWeight: 600 }}>
                ✓ Toàn bộ {summary.safePackages ?? results.length} gói thư viện đã được xác minh thành công và không phát hiện lỗ hổng bảo mật.
              </div>
            )
          ) : (
            <div className="table-responsive">
              <table style={{ width: '100%', minWidth: 600, borderCollapse: 'collapse', fontSize: 13, textAlign: 'left', fontFamily: "'Times New Roman', Times, serif" }}>
                <thead>
                  <tr style={{ background: '#f1f5f9', borderBottom: '2px solid #cbd5e1' }}>
                    <th style={{ padding: '8px 10px', color: '#1e293b', fontWeight: 700 }}>STT</th>
                    <th style={{ padding: '8px 10px', color: '#1e293b', fontWeight: 700 }}>THƯ VIỆN</th>
                    <th style={{ padding: '8px 10px', color: '#1e293b', fontWeight: 700 }}>PHIÊN BẢN</th>
                    <th style={{ padding: '8px 10px', color: '#1e293b', fontWeight: 700 }}>SỐ LỖ HỔNG</th>
                    <th style={{ padding: '8px 10px', color: '#1e293b', fontWeight: 700 }}>CISA KEV</th>
                    <th style={{ padding: '8px 10px', color: '#1e293b', fontWeight: 700 }}>BẢN VÁ KHUYẾN NGHỊ</th>
                  </tr>
                </thead>
                <tbody>
                  {vulnerablePackages.map((pkg, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid #e2e8f0', background: '#fffafa' }}>
                      <td style={{ padding: '8px 10px', color: '#475569' }}>{i + 1}</td>
                      <td style={{ padding: '8px 10px', fontWeight: 700 }}>
                        {pkg.package}
                      </td>
                      <td style={{ padding: '8px 10px' }}>
                        v{pkg.version}
                      </td>
                      <td style={{ padding: '8px 10px' }}>
                        <span style={{ color: '#b91c1c', fontWeight: 700 }}>
                          {pkg.totalVulnerabilities || pkg.vulnerabilities?.length || 0} CVEs
                        </span>
                      </td>
                      <td style={{ padding: '8px 10px' }}>
                        {pkg.hasCisaKev ? (
                          <span style={{ color: '#dc2626', fontWeight: 700 }}>⚠️ CISA KEV</span>
                        ) : (
                          <span style={{ color: '#475569' }}>Không</span>
                        )}
                      </td>
                      <td style={{ padding: '8px 10px' }}>
                        {pkg.fixedVersion ? (
                          <strong style={{ color: '#0284c7' }}>
                            Nâng lên &gt;= {pkg.fixedVersion}
                          </strong>
                        ) : (
                          <span style={{ color: '#d97706' }}>Chưa có bản vá</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Section 2: Detailed Breakdown of ALL Vulnerabilities */}
        {vulnerablePackages.length > 0 && (
          <div style={{ marginBottom: 24 }}>
            <h2 style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', borderBottom: '1px solid #cbd5e1', paddingBottom: 6, marginBottom: 16, fontFamily: "'Times New Roman', Times, serif" }}>
              II. CHI TIẾT TẤT CẢ CÁC LỖ HỔNG BẢO MẬT PHÁT HIỆN ĐƯỢC
            </h2>

            {vulnerablePackages.map((pkg, pIdx) => (
              <div key={pIdx} style={{ marginBottom: 22, border: '1px solid #cbd5e1', borderRadius: 6, overflow: 'hidden' }}>
                <div style={{
                  background: '#f1f5f9',
                  padding: '10px 14px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  borderBottom: '1px solid #cbd5e1'
                }}>
                  <div>
                    <strong style={{ fontSize: 15, color: '#0f172a' }}>
                      {pIdx + 1}. Thư viện: <span style={{ color: '#1e3a8a' }}>{pkg.package}</span> (v{pkg.version})
                    </strong>
                  </div>
                  <div style={{ fontSize: 13 }}>
                    Bản vá an toàn: <strong style={{ color: pkg.fixedVersion ? '#0284c7' : '#d97706' }}>
                      {pkg.fixedVersion ? `>= ${pkg.fixedVersion}` : 'Chưa có bản vá'}
                    </strong>
                  </div>
                </div>

                <div style={{ padding: 12 }}>
                  {(pkg.vulnerabilities || []).map((vuln, vIdx) => {
                    const sevUpper = (vuln.severity || '').toUpperCase().trim();
                    const badgeColor =
                      sevUpper === 'CRITICAL' ? '#dc2626' :
                      sevUpper === 'HIGH' ? '#ea580c' :
                      sevUpper === 'MEDIUM' ? '#2563eb' :
                      sevUpper === 'LOW' ? '#4b5563' : '#d97706';

                    return (
                      <div key={vIdx} style={{
                        padding: '10px 12px',
                        background: '#ffffff',
                        border: '1px solid #e2e8f0',
                        borderRadius: 6,
                        marginBottom: 10
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6, flexWrap: 'wrap', gap: 6 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span style={{ fontWeight: 800, color: '#1e293b', fontSize: 14 }}>
                              {vuln.id}
                            </span>
                            {vuln.aliases && vuln.aliases.length > 0 && (
                              <span style={{ fontSize: 12, color: '#64748b' }}>
                                ({vuln.aliases.slice(0, 2).join(', ')})
                              </span>
                            )}
                          </div>

                          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                            <span style={{
                              fontSize: 11,
                              fontWeight: 800,
                              color: '#ffffff',
                              background: badgeColor,
                              padding: '2px 8px',
                              borderRadius: 4
                            }}>
                              {vuln.severity || 'UNKNOWN'}
                            </span>
                            {vuln.isCisaKev && (
                              <span style={{
                                fontSize: 11,
                                fontWeight: 800,
                                color: '#ffffff',
                                background: '#dc2626',
                                padding: '2px 8px',
                                borderRadius: 4
                              }}>
                                CISA KEV
                              </span>
                            )}
                          </div>
                        </div>

                        <div style={{ fontSize: 13, color: '#334155', lineHeight: 1.5 }}>
                          {vuln.summary || vuln.details || 'Không có mô tả chi tiết'}
                        </div>

                        {vuln.isCisaKev && vuln.cisaKevDetails && (
                          <div style={{ marginTop: 6, padding: '6px 10px', background: '#fef2f2', borderRadius: 4, fontSize: 12, color: '#991b1b' }}>
                            <strong>Chỉ thị CISA KEV:</strong> {vuln.cisaKevDetails.requiredAction || vuln.cisaKevDetails.vulnerabilityName}
                          </div>
                        )}

                        {vuln.references && vuln.references.length > 0 && (
                          <div style={{ marginTop: 6, fontSize: 12, color: '#0284c7' }}>
                            <span style={{ color: '#64748b' }}>Tham chiếu: </span>
                            <a href={vuln.references[0]} target="_blank" rel="noopener noreferrer" style={{ color: '#0284c7', textDecoration: 'underline' }}>
                              {vuln.references[0]}
                            </a>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

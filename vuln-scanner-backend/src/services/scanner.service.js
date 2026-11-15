const axios = require('axios');
const { OSV_API_URL } = require('../config/constants');
const CisaService = require('./cisa.service');
const ExploitDbService = require('./exploitdb.service');

class ScannerService {
  /**
   * Trích xuất phiên bản đã vá lỗi (Fixed Version) từ cấu trúc affected của OSV
   */
  static extractFixedVersion(affectedList) {
    if (!affectedList || !Array.isArray(affectedList)) return null;

    const fixedVersions = [];
    for (const item of affectedList) {
      if (item.ranges && Array.isArray(item.ranges)) {
        for (const range of item.ranges) {
          if (range.events && Array.isArray(range.events)) {
            for (const event of range.events) {
              if (event.fixed) {
                fixedVersions.push(event.fixed);
              }
            }
          }
        }
      }
    }

    if (fixedVersions.length === 0) return null;
    // Trả về phiên bản vá cao nhất/mới nhất tìm thấy
    return fixedVersions[fixedVersions.length - 1];
  }

  /**
   * Chuẩn hóa mức độ nghiêm trọng (Severity)
   */
  static normalizeSeverity(vuln) {
    if (vuln.database_specific && vuln.database_specific.severity) {
      const s = vuln.database_specific.severity.toUpperCase();
      if (s === 'CRITICAL' || s === 'HIGH' || s === 'MEDIUM' || s === 'MODERATE' || s === 'LOW') {
        return s === 'MODERATE' ? 'MEDIUM' : s;
      }
    }
    // Nếu có CVSS
    if (vuln.severity && Array.isArray(vuln.severity) && vuln.severity.length > 0) {
      return 'HIGH'; // Mặc định nếu có CVSS
    }
    return 'UNKNOWN';
  }

  /**
   * Truy vấn OSV cho một thư viện cụ thể với phân tách khối lỗi độc lập (AUD-01)
   */
  static async queryOsv(name, version, ecosystem) {
    let rawVulns = [];
    let osvError = null;

    // KHỐI 1: Truy vấn Google OSV API độc lập
    try {
      const response = await axios.post(
        OSV_API_URL,
        {
          package: {
            name: name,
            ecosystem: ecosystem
          },
          version: version
        },
        { timeout: 10000 }
      );

      if (response.data && Array.isArray(response.data.vulns)) {
        rawVulns = response.data.vulns;
      }
    } catch (error) {
      osvError = error.code === 'ECONNABORTED'
        ? 'Kết nối tới OSV API bị quá thời gian (timeout 10s)'
        : (error.response?.data?.message || error.message || 'Lỗi truy vấn OSV API');
      console.error(`[-] [OSV Error] Thư viện ${name}@${version}:`, osvError);

      // QUAN TRỌNG (AUD-01): Lỗi nguồn OSV trả về trạng thái error rõ ràng,
      // KHÔNG nuốt lỗi thành mảng rỗng [] khiến thư viện bị đánh nhãn sai thành SAFE!
      return {
        success: false,
        status: 'error',
        errorMessage: osvError,
        vulnerabilities: [],
        sources: {
          osv: { status: 'error', error: osvError },
          cisaKev: { status: 'skipped', error: null },
          exploitDb: { status: 'skipped', error: null }
        }
      };
    }

    // Nếu OSV thành công và không phát hiện lỗ hổng
    if (rawVulns.length === 0) {
      return {
        success: true,
        status: 'scanned',
        errorMessage: null,
        vulnerabilities: [],
        sources: {
          osv: { status: 'success', error: null },
          cisaKev: { status: 'skipped', error: null },
          exploitDb: { status: 'skipped', error: null }
        }
      };
    }

    // Thu thập toàn bộ ID và alias CVE để đối chiếu nguồn dữ liệu phụ
    const allCandidateCves = [];
    const parsedVulns = rawVulns.map((v) => {
      const aliases = Array.isArray(v.aliases) ? v.aliases : [];
      const candidateCves = [v.id, ...aliases].filter((c) => c && c.startsWith('CVE-'));
      allCandidateCves.push(...candidateCves);

      return {
        id: v.id,
        aliases: aliases,
        candidateCves: candidateCves,
        summary: v.summary || 'Không có mô tả ngắn',
        details: v.details || '',
        severity: this.normalizeSeverity(v),
        fixed: this.extractFixedVersion(v.affected),
        references: (v.references || []).map((r) => r.url).slice(0, 5)
      };
    });

    // KHỐI 2: Đối chiếu chéo với CISA KEV trong try/catch độc lập
    let cisaMap = new Map();
    let cisaStatus = 'success';
    let cisaError = null;
    try {
      cisaMap = await CisaService.checkVulnerabilities(allCandidateCves);
    } catch (err) {
      cisaStatus = 'error';
      cisaError = err.message || 'Lỗi đối chiếu CISA KEV';
      console.warn(`[!] [CISA KEV Warning] Không thể đối chiếu KEV cho ${name}:`, cisaError);
    }

    // KHỐI 3: Kiểm tra Exploit-DB PoC trong try/catch độc lập
    let exploitDbStatus = 'success';
    let exploitDbError = null;

    // Gắn kết quả CISA KEV và Exploit-DB vào từng lỗ hổng mà không làm mất phát hiện OSV
    const finalVulns = parsedVulns.map((v) => {
      let isCisaKev = false;
      let cisaKevDetails = null;
      const exploitDbList = [];

      for (const cve of v.candidateCves) {
        const upperCve = cve.toUpperCase();

        if (cisaMap.has(upperCve)) {
          isCisaKev = true;
          const cisaRecord = cisaMap.get(upperCve);
          cisaKevDetails = {
            cveID: cisaRecord.cveID,
            vulnerabilityName: cisaRecord.vulnerabilityName,
            dateAdded: cisaRecord.dateAdded,
            requiredAction: cisaRecord.requiredAction,
            knownRansomwareCampaignUse: cisaRecord.knownRansomwareCampaignUse
          };
        }

        try {
          const edbMatches = ExploitDbService.findExploitsByCve(upperCve);
          if (edbMatches && edbMatches.length > 0) {
            exploitDbList.push(...edbMatches);
          }
        } catch (edbErr) {
          exploitDbStatus = 'error';
          exploitDbError = edbErr.message;
        }
      }

      const { candidateCves, ...finalVuln } = v;
      return {
        ...finalVuln,
        isCisaKev: isCisaKev,
        cisaKevDetails: cisaKevDetails,
        hasExploitDb: exploitDbList.length > 0,
        exploitDbList: exploitDbList
      };
    });

    const isPartial = cisaStatus === 'error' || exploitDbStatus === 'error';

    return {
      success: true,
      status: isPartial ? 'partial' : 'scanned',
      errorMessage: cisaError || exploitDbError || null,
      vulnerabilities: finalVulns,
      sources: {
        osv: { status: 'success', error: null },
        cisaKev: { status: cisaStatus, error: cisaError },
        exploitDb: { status: exploitDbStatus, error: exploitDbError }
      }
    };
  }

  /**
   * Quét toàn bộ danh sách gói phụ thuộc (hỗ trợ Promise.all theo lô để tối ưu tốc độ)
   */
  static async scanDependencies(packages) {
    const scanResults = [];
    const batchSize = 10; // Quét đồng thời 10 packages để không bị timeout

    for (let i = 0; i < packages.length; i += batchSize) {
      const batch = packages.slice(i, i + batchSize);
      const batchPromises = batch.map(async (pkg) => {
        const queryRes = await this.queryOsv(pkg.name, pkg.version, pkg.ecosystem);
        const isSuccess = queryRes.success;
        const vulnerabilities = queryRes.vulnerabilities || [];
        const hasCisaKev = vulnerabilities.some((v) => v.isCisaKev);
        const hasExploitDb = vulnerabilities.some((v) => v.hasExploitDb);

        // Tìm phiên bản vá lỗi được gợi ý (nếu có)
        const fixedVersions = vulnerabilities
          .map((v) => v.fixed)
          .filter(Boolean);
        const recommendedFixedVersion = fixedVersions.length > 0 ? fixedVersions[fixedVersions.length - 1] : null;

        return {
          package: pkg.name,
          version: pkg.version,
          ecosystem: pkg.ecosystem,
          scanStatus: queryRes.status, // 'scanned' | 'error' | 'partial'
          scanError: queryRes.errorMessage,
          sources: queryRes.sources,
          isVulnerable: isSuccess ? vulnerabilities.length > 0 : false,
          isSafe: isSuccess && vulnerabilities.length === 0, // AUD-01: Chỉ an toàn khi truy vấn OSV thành công và không có lỗ hổng
          hasScanError: !isSuccess,
          hasCisaKev: hasCisaKev,
          hasExploitDb: hasExploitDb,
          totalVulnerabilities: vulnerabilities.length,
          fixedVersion: recommendedFixedVersion,
          vulnerabilities: vulnerabilities
        };
      });

      const batchResults = await Promise.all(batchPromises);
      scanResults.push(...batchResults);
    }

    return scanResults;
  }

  /**
   * Tính toán điểm số rủi ro (Risk Score: 0-100) và cấp độ rủi ro (Risk Level)
   */
  static calculateRisk(scanResults) {
    let totalVulns = 0;
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;
    let cisaKevCount = 0;
    let exploitDbCount = 0;
    let errorCount = 0;

    for (const item of scanResults) {
      if (item.hasScanError || item.scanStatus === 'error') {
        errorCount++;
      }

      if (item.isVulnerable) {
        totalVulns += item.totalVulnerabilities;
        if (item.hasCisaKev) cisaKevCount += 1;
        if (item.hasExploitDb) exploitDbCount += 1;

        for (const v of item.vulnerabilities) {
          if (v.isCisaKev) cisaKevCount += 1;
          if (v.hasExploitDb) exploitDbCount += (v.exploitDbList || []).length;
          const sev = (v.severity || '').toUpperCase();
          if (sev === 'CRITICAL') criticalCount++;
          else if (sev === 'HIGH') highCount++;
          else if (sev === 'MEDIUM') mediumCount++;
          else if (sev === 'LOW') lowCount++;
        }
      }
    }

    // Nếu dính CISA KEV hoặc Exploit-DB PoC -> Rủi ro cao vì đã có mã khai thác công khai
    let riskLevel = 'SAFE';
    let riskScore = 0;

    if (cisaKevCount > 0 || exploitDbCount > 0 || criticalCount > 0) {
      riskLevel = 'CRITICAL';
      riskScore = Math.min(100, 85 + (cisaKevCount * 5) + (exploitDbCount * 3) + (criticalCount * 3));
    } else if (highCount > 0) {
      riskLevel = 'HIGH';
      riskScore = Math.min(84, 60 + (highCount * 5));
    } else if (mediumCount > 0) {
      riskLevel = 'MEDIUM';
      riskScore = Math.min(59, 30 + (mediumCount * 5));
    } else if (lowCount > 0) {
      riskLevel = 'LOW';
      riskScore = Math.min(29, 10 + (lowCount * 3));
    } else if (errorCount > 0) {
      // AUD-01: Nếu không phát hiện lỗ hổng nhưng có gói bị lỗi truy vấn OSV,
      // KHÔNG ĐƯỢC kết luận SAFE! Đánh dấu INCONCLUSIVE (chưa đủ dữ liệu kết luận)
      riskLevel = 'INCONCLUSIVE';
      riskScore = 0;
    } else {
      riskLevel = 'SAFE';
      riskScore = 0;
    }

    return {
      riskScore,
      riskLevel,
      cisaKevCount,
      exploitDbCount,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      errorCount,
      hasScanErrors: errorCount > 0
    };
  }
}

module.exports = ScannerService;
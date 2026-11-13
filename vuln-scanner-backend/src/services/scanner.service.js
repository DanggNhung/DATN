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
   * Truy vấn OSV cho một thư viện cụ thể
   */
  static async queryOsv(name, version, ecosystem) {
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

      if (!response.data || !response.data.vulns || !Array.isArray(response.data.vulns)) {
        return [];
      }

      // Thu thập toàn bộ ID và alias CVE để đối chiếu với CISA KEV
      const allCandidateCves = [];
      const parsedVulns = response.data.vulns.map((v) => {
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

      // Đối chiếu chéo với CISA KEV
      const cisaMap = await CisaService.checkVulnerabilities(allCandidateCves);

      // Gắn kết quả CISA KEV và Exploit-DB vào từng lỗ hổng
      return parsedVulns.map((v) => {
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

          // Kiểm tra Exploit-DB PoC
          const edbMatches = ExploitDbService.findExploitsByCve(upperCve);
          if (edbMatches.length > 0) {
            exploitDbList.push(...edbMatches);
          }
        }

        // Loại bỏ trường tạm candidateCves
        const { candidateCves, ...finalVuln } = v;
        return {
          ...finalVuln,
          isCisaKev: isCisaKev,
          cisaKevDetails: cisaKevDetails,
          hasExploitDb: exploitDbList.length > 0,
          exploitDbList: exploitDbList
        };
      });
    } catch (error) {
      return [];
    }
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
        const vulnerabilities = await this.queryOsv(pkg.name, pkg.version, pkg.ecosystem);
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
          isVulnerable: vulnerabilities.length > 0,
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

    for (const item of scanResults) {
      if (item.isVulnerable) {
        totalVulns += item.totalVulnerabilities;
        if (item.hasCisaKev) cisaKevCount += 1;
        if (item.hasExploitDb) exploitDbCount += 1;

        for (const v of item.vulnerabilities) {
          if (v.isCisaKev) cisaKevCount += 1;
          if (v.hasExploitDb) exploitDbCount += (v.exploitDbList || []).length;
          const sev = v.severity.toUpperCase();
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
      lowCount
    };
  }
}

module.exports = ScannerService;
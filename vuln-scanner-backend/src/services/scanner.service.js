const axios = require('axios');
const { OSV_API_URL } = require('../config/constants');
const CisaService = require('./cisa.service');
const ExploitDbService = require('./exploitdb.service');

class ScannerService {
  /**
   * So sánh 2 chuỗi phiên bản theo SemVer/PEP440 (trả về >0 nếu a > b, <0 nếu a < b, 0 nếu bằng)
   */
  static compareVersions(a, b) {
    const normalize = (v) => String(v || '').trim().replace(/^v(?=\d)/i, '');
    const va = normalize(a);
    const vb = normalize(b);
    if (va === vb) return 0;

    const [mainA, preA] = va.split('-', 2);
    const [mainB, preB] = vb.split('-', 2);

    const partsA = mainA.split('.').map((p) => (/^\d+$/.test(p) ? parseInt(p, 10) : p));
    const partsB = mainB.split('.').map((p) => (/^\d+$/.test(p) ? parseInt(p, 10) : p));
    const len = Math.max(partsA.length, partsB.length);

    for (let i = 0; i < len; i++) {
      const pa = partsA[i] !== undefined ? partsA[i] : 0;
      const pb = partsB[i] !== undefined ? partsB[i] : 0;
      if (typeof pa === 'number' && typeof pb === 'number') {
        if (pa !== pb) return pa - pb;
      } else {
        const sa = String(pa);
        const sb = String(pb);
        if (sa !== sb) return sa.localeCompare(sb);
      }
    }

    // Phiên bản chính thức (không có pre-release) cao hơn pre-release
    if (!preA && preB) return 1;
    if (preA && !preB) return -1;
    if (preA && preB) return preA.localeCompare(preB);
    return 0;
  }

  /**
   * Chọn phiên bản cao nhất từ mảng các phiên bản (không phụ thuộc thứ tự mảng)
   */
  static pickHighestVersion(versions) {
    const valid = (versions || []).filter(Boolean);
    if (valid.length === 0) return null;
    return valid.reduce((best, curr) => (this.compareVersions(curr, best) > 0 ? curr : best), valid[0]);
  }

  /**
   * Trích xuất phiên bản đã vá lỗi (Fixed Version) cao nhất từ cấu trúc affected của OSV
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

    return this.pickHighestVersion(fixedVersions);
  }

  /**
   * Tính điểm CVSS Base Score chuẩn từ chuỗi vector CVSS v3.0 / v3.1 hoặc CVSS v2.0
   */
  static calculateCvssBaseScore(vectorStr) {
    if (typeof vectorStr !== 'string') return null;
    const vector = vectorStr.trim().toUpperCase();

    // CVSS v3.0 / v3.1
    if (vector.startsWith('CVSS:3.0/') || vector.startsWith('CVSS:3.1/')) {
      const metrics = {};
      for (const part of vector.split('/').slice(1)) {
        const [k, v] = part.split(':');
        if (k && v) metrics[k] = v;
      }

      const avMap = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
      const acMap = { L: 0.77, H: 0.44 };
      const uiMap = { N: 0.85, R: 0.62 };
      const ciaMap = { H: 0.56, L: 0.22, N: 0.0 };
      const prUnchanged = { N: 0.85, L: 0.62, H: 0.27 };
      const prChanged = { N: 0.85, L: 0.68, H: 0.5 };

      const av = avMap[metrics.AV];
      const ac = acMap[metrics.AC];
      const scope = metrics.S;
      const pr = scope === 'C' ? prChanged[metrics.PR] : scope === 'U' ? prUnchanged[metrics.PR] : undefined;
      const ui = uiMap[metrics.UI];
      const c = ciaMap[metrics.C];
      const i = ciaMap[metrics.I];
      const a = ciaMap[metrics.A];

      if ([av, ac, pr, ui, c, i, a].some((x) => x === undefined)) {
        return null;
      }

      const iss = 1 - (1 - c) * (1 - i) * (1 - a);
      if (iss <= 0) return 0;

      const impact = scope === 'C'
        ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
        : 6.42 * iss;
      if (impact <= 0) return 0;

      const exploitability = 8.22 * av * ac * pr * ui;
      const rawScore = scope === 'C'
        ? Math.min(1.08 * (impact + exploitability), 10)
        : Math.min(impact + exploitability, 10);

      // Roundup theo chuẩn FIRST.org (tránh sai số dấu phẩy động)
      return Math.ceil(Math.round(rawScore * 100000) / 10000) / 10;
    }

    // CVSS v2.0
    if (vector.startsWith('AV:') || vector.startsWith('CVSS:2.0/')) {
      const clean = vector.replace(/^CVSS:2\.0\//, '');
      const metrics = {};
      for (const part of clean.split('/')) {
        const [k, v] = part.split(':');
        if (k && v) metrics[k] = v;
      }

      const avMap = { L: 0.395, A: 0.646, N: 1.0 };
      const acMap = { H: 0.35, M: 0.61, L: 0.71 };
      const auMap = { M: 0.45, S: 0.56, N: 0.704 };
      const ciaMap = { N: 0.0, P: 0.275, C: 0.66 };

      const av = avMap[metrics.AV];
      const ac = acMap[metrics.AC];
      const au = auMap[metrics.AU];
      const c = ciaMap[metrics.C];
      const i = ciaMap[metrics.I];
      const a = ciaMap[metrics.A];

      if ([av, ac, au, c, i, a].some((x) => x === undefined)) {
        return null;
      }

      const impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a));
      const exploitability = 20 * av * ac * au;
      const fImpact = impact === 0 ? 0 : 1.176;
      const baseScore = (0.6 * impact + 0.4 * exploitability - 1.5) * fImpact;
      return Math.max(0, Math.round(baseScore * 10) / 10);
    }

    return null;
  }

  /**
   * Chuẩn hóa mức độ nghiêm trọng (Severity)
   * AUD-02: Nhận diện chính xác string severity, CVSS numeric score, database_specific và tính điểm chuẩn từ vector CVSS
   */
  static normalizeSeverity(vuln) {
    if (!vuln) return 'UNKNOWN';

    // 1. Nếu vuln.severity là chuỗi ký tự (CRITICAL, HIGH, MEDIUM, LOW, MODERATE, UNKNOWN)
    if (typeof vuln.severity === 'string') {
      const s = vuln.severity.trim().toUpperCase();
      if (['CRITICAL', 'HIGH', 'MEDIUM', 'MODERATE', 'LOW', 'UNKNOWN'].includes(s)) {
        return s === 'MODERATE' ? 'MEDIUM' : s;
      }
    }

    // 2. Nếu có database_specific.severity
    if (vuln.database_specific && vuln.database_specific.severity) {
      const s = String(vuln.database_specific.severity).trim().toUpperCase();
      if (['CRITICAL', 'HIGH', 'MEDIUM', 'MODERATE', 'LOW'].includes(s)) {
        return s === 'MODERATE' ? 'MEDIUM' : s;
      }
    }

    // 3. Nếu có ecosystem_specific.severity
    if (vuln.ecosystem_specific && vuln.ecosystem_specific.severity) {
      const s = String(vuln.ecosystem_specific.severity).trim().toUpperCase();
      if (['CRITICAL', 'HIGH', 'MEDIUM', 'MODERATE', 'LOW'].includes(s)) {
        return s === 'MODERATE' ? 'MEDIUM' : s;
      }
    }

    // 4. Nếu có mảng CVSS (OSV Schema)
    if (Array.isArray(vuln.severity) && vuln.severity.length > 0) {
      for (const item of vuln.severity) {
        if (!item) continue;
        const numericScore = parseFloat(item.score);
        if (!isNaN(numericScore) && numericScore > 0) {
          if (numericScore >= 9.0) return 'CRITICAL';
          if (numericScore >= 7.0) return 'HIGH';
          if (numericScore >= 4.0) return 'MEDIUM';
          return 'LOW';
        }

        if (typeof item.score === 'string') {
          const calculatedScore = this.calculateCvssBaseScore(item.score);
          if (calculatedScore !== null) {
            if (calculatedScore >= 9.0) return 'CRITICAL';
            if (calculatedScore >= 7.0) return 'HIGH';
            if (calculatedScore >= 4.0) return 'MEDIUM';
            if (calculatedScore > 0) return 'LOW';
            return 'UNKNOWN';
          }
        }
      }
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
      const exploitDbMap = new Map();

      for (const cve of v.candidateCves) {
        const upperCve = cve.toUpperCase();

        if (!isCisaKev && cisaMap.has(upperCve)) {
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
            for (const edb of edbMatches) {
              const edbKey = edb.edbId || edb.id || edb.url || JSON.stringify(edb);
              if (!exploitDbMap.has(edbKey)) {
                exploitDbMap.set(edbKey, edb);
              }
            }
          }
        } catch (edbErr) {
          exploitDbStatus = 'error';
          exploitDbError = edbErr.message;
        }
      }

      const exploitDbList = Array.from(exploitDbMap.values());
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

        // Tìm phiên bản vá lỗi cao nhất được gợi ý (nếu có)
        const fixedVersions = vulnerabilities
          .map((v) => v.fixed)
          .filter(Boolean);
        const recommendedFixedVersion = this.pickHighestVersion(fixedVersions);

        return {
          package: pkg.name,
          version: pkg.version,
          versionRange: pkg.versionRange || null,
          isVersionRange: Boolean(pkg.isVersionRange),
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
   * AUD-01: Phân tách độc lập lỗi kết nối nguồn OSV (INCONCLUSIVE) vs An toàn (SAFE)
   * AUD-02: Lỗ hổng có severity UNKNOWN không được đánh giá SAFE; phản ánh thành INCONCLUSIVE (Chưa đủ dữ liệu đánh giá)
   */
  static calculateRisk(scanResults) {
    let totalVulns = 0;
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;
    let unknownCount = 0;
    let cisaKevCount = 0;
    let exploitDbCount = 0;
    let errorCount = 0;
    let vulnerablePackagesCount = 0;

    for (const item of (scanResults || [])) {
      if (!item) continue;

      if (item.hasScanError || item.scanStatus === 'error') {
        errorCount++;
      }

      if (item.isVulnerable) {
        vulnerablePackagesCount++;
        const itemVulns = Array.isArray(item.vulnerabilities) ? item.vulnerabilities : [];
        const declaredTotal = typeof item.totalVulnerabilities === 'number' ? item.totalVulnerabilities : itemVulns.length;
        const countToAdd = Math.max(declaredTotal, itemVulns.length);
        totalVulns += countToAdd;

        // Thống kê nhất quán ở cấp độ lỗ hổng (mỗi lỗ hổng chỉ cộng tối đa 1 KEV / 1 PoC)
        for (const v of itemVulns) {
          if (!v) continue;
          if (v.isCisaKev) cisaKevCount++;
          if (v.hasExploitDb || (Array.isArray(v.exploitDbList) && v.exploitDbList.length > 0)) {
            exploitDbCount++;
          }
          const sev = (v.severity || '').toUpperCase().trim();
          if (sev === 'CRITICAL') criticalCount++;
          else if (sev === 'HIGH') highCount++;
          else if (sev === 'MEDIUM' || sev === 'MODERATE') mediumCount++;
          else if (sev === 'LOW') lowCount++;
          else unknownCount++;
        }

        // Trường hợp package dính lỗ hổng nhưng không có mảng chi tiết hoặc mảng rỗng
        if (itemVulns.length === 0) {
          if (item.hasCisaKev) cisaKevCount++;
          if (item.hasExploitDb) exploitDbCount++;
          unknownCount += Math.max(declaredTotal, 1);
        }
      }
    }

    // Nếu dính CISA KEV hoặc Exploit-DB PoC -> Rủi ro cao vì đã có mã khai thác công khai
    let riskLevel = 'SAFE';
    let riskScore = 0;

    if (cisaKevCount > 0 || exploitDbCount > 0 || criticalCount > 0) {
      riskLevel = 'CRITICAL';
      riskScore = Math.min(100, 85 + (cisaKevCount * 5) + (exploitDbCount * 3) + (criticalCount * 3) + (highCount * 2) + (unknownCount * 1));
    } else if (highCount > 0) {
      riskLevel = 'HIGH';
      riskScore = Math.min(84, 60 + (highCount * 5) + (mediumCount * 2) + (unknownCount * 2));
    } else if (mediumCount > 0) {
      riskLevel = 'MEDIUM';
      riskScore = Math.min(59, 30 + (mediumCount * 5) + (lowCount * 2) + (unknownCount * 2));
    } else if (lowCount > 0) {
      riskLevel = 'LOW';
      riskScore = Math.min(29, 10 + (lowCount * 3) + (unknownCount * 2));
    } else if (unknownCount > 0 || vulnerablePackagesCount > 0 || totalVulns > 0) {
      // AUD-02: Có lỗ hổng bảo mật nhưng chỉ có mức độ UNKNOWN (chưa có điểm CVSS)
      // TUYỆT ĐỐI KHÔNG ĐƯỢC kết luận SAFE! Phản ánh thành chưa đủ dữ liệu đánh giá (INCONCLUSIVE)
      // Ghi nhận điểm cảnh báo tối thiểu thay vì 0 điểm an toàn
      riskLevel = 'INCONCLUSIVE';
      riskScore = Math.min(35, 15 + (unknownCount * 3));
    } else if (errorCount > 0) {
      // AUD-01: Không phát hiện lỗ hổng nhưng có gói bị lỗi truy vấn nguồn OSV,
      // KHÔNG ĐƯỢC kết luận SAFE! Đánh dấu INCONCLUSIVE (chưa đủ dữ liệu kết luận)
      riskLevel = 'INCONCLUSIVE';
      riskScore = 0;
    } else {
      // Chỉ khi toàn bộ gói quét thành công và 0 lỗ hổng mới kết luận SAFE
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
      unknownCount,
      totalVulns,
      vulnerablePackagesCount,
      errorCount,
      hasScanErrors: errorCount > 0,
      hasUnknownSeverity: unknownCount > 0
    };
  }
}

module.exports = ScannerService;
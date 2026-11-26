const axios = require('axios');
const url = require('url');
const ExploitDbService = require('./exploitdb.service');

class DastService {
  static ZAP_HOST = process.env.ZAP_HOST || 'http://127.0.0.1:8080';
  static ZAP_API_KEY = process.env.ZAP_API_KEY || '';

  /**
   * Kiểm tra xem OWASP ZAP Daemon có đang chạy và sẵn sàng nhận lệnh không
   */
  static async checkZapStatus() {
    try {
      const response = await axios.get(`${this.ZAP_HOST}/JSON/core/view/version/`, {
        timeout: 2000,
        headers: this.ZAP_API_KEY ? { 'X-ZAP-API-Key': this.ZAP_API_KEY } : {}
      });

      if (response.data && response.data.version) {
        return {
          isAvailable: true,
          version: response.data.version,
          host: this.ZAP_HOST
        };
      }
    } catch (e) {
      // ZAP không chạy
    }

    return {
      isAvailable: false,
      message: 'OWASP ZAP Daemon không chạy trên cổng 8080. Sẽ sử dụng SecShield Automated DAST Engine tích hợp sẵn.',
      host: this.ZAP_HOST
    };
  }

  /**
   * Bộ kiểm thử động Baseline tự động theo chuẩn OWASP Top 10 API Security
   */
  static async runBuiltinDastAssessment(targetUrl) {
    const alerts = [];
    const startTime = Date.now();

    // Chuẩn hóa URL
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      targetUrl = 'http://' + targetUrl;
    }

    const parsedUrl = new URL(targetUrl);
    const client = axios.create({
      timeout: 10000,
      validateStatus: () => true // Bắt mọi status code kể cả 4xx, 5xx
    });

    try {
      // Test 1: Kiểm thử yêu cầu tiêu chuẩn & phân tích HTTP Response Headers
      const normalRes = await client.get(targetUrl);
      const headers = normalRes.headers;

      // 1.1 Kiểm tra thiếu Content-Security-Policy (CSP)
      if (!headers['content-security-policy']) {
        alerts.push({
          name: 'Thiếu Header Content-Security-Policy (CSP)',
          risk: 'Medium',
          confidence: 'High',
          cweId: 'CWE-1021',
          description: 'Ứng dụng không thiết lập Content-Security-Policy. Kẻ tấn công có thể lợi dụng để thực hiện các cuộc tấn công Cross-Site Scripting (XSS) hoặc chèn dữ liệu độc hại.',
          solution: 'Bổ sung header Content-Security-Policy để giới hạn các nguồn tài nguyên (scripts, styles, images) được phép tải trên trình duyệt.',
          url: targetUrl,
          method: 'GET',
          parameter: 'Header: Content-Security-Policy',
          evidence: 'Header không tồn tại trong phản hồi của server'
        });
      }

      // 1.2 Kiểm tra thiếu X-Content-Type-Options
      if (!headers['x-content-type-options'] || headers['x-content-type-options'].toLowerCase() !== 'nosniff') {
        alerts.push({
          name: 'Thiếu Header X-Content-Type-Options: nosniff',
          risk: 'Low',
          confidence: 'High',
          cweId: 'CWE-693',
          description: 'Trình duyệt có thể tự ý suy đoán định dạng MIME (MIME-sniffing) và thực thi các tệp nội dung tải lên như mã thực thi.',
          solution: 'Thêm cấu hình header: X-Content-Type-Options: nosniff vào phản hồi của máy chủ.',
          url: targetUrl,
          method: 'GET',
          parameter: 'Header: X-Content-Type-Options',
          evidence: headers['x-content-type-options'] || 'Header không tồn tại'
        });
      }

      // 1.3 Kiểm tra Clickjacking (X-Frame-Options)
      if (!headers['x-frame-options'] && !headers['content-security-policy']?.includes('frame-ancestors')) {
        alerts.push({
          name: 'Thiếu cơ chế chống Clickjacking (X-Frame-Options)',
          risk: 'Medium',
          confidence: 'High',
          cweId: 'CWE-1021',
          description: 'Trang web có thể bị nhúng vào bên trong thẻ <iframe> trên website của tin tặc để lừa người dùng nhấp chuột vào các nút hành động nhạy cảm.',
          solution: 'Thiết lập header: X-Frame-Options: DENY hoặc SAMEORIGIN.',
          url: targetUrl,
          method: 'GET',
          parameter: 'Header: X-Frame-Options',
          evidence: 'Không phát hiện X-Frame-Options hoặc frame-ancestors'
        });
      }

      // 1.4 Kiểm tra HSTS nếu chạy HTTPS
      if (parsedUrl.protocol === 'https:' && !headers['strict-transport-security']) {
        alerts.push({
          name: 'Thiếu Header HTTP Strict Transport Security (HSTS)',
          risk: 'Low',
          confidence: 'High',
          cweId: 'CWE-319',
          description: 'Ứng dụng HTTPS chưa cấu hình HSTS. Người dùng có nguy cơ bị tấn công hạ cấp giao thức xuống HTTP không mã hóa (SSL Strip).',
          solution: 'Bổ sung header: Strict-Transport-Security: max-age=31536000; includeSubDomains.',
          url: targetUrl,
          method: 'GET',
          parameter: 'Header: Strict-Transport-Security',
          evidence: 'Header HSTS không tồn tại'
        });
      }

      // 1.5 Kiểm tra lộ thông tin công nghệ máy chủ (Server Information Disclosure)
      if (headers['server'] || headers['x-powered-by'] || headers['x-aspnet-version']) {
        const leaked = [
          headers['server'] ? `Server: ${headers['server']}` : null,
          headers['x-powered-by'] ? `X-Powered-By: ${headers['x-powered-by']}` : null
        ].filter(Boolean).join(', ');

        alerts.push({
          name: 'Lộ Thông Tin Ngăn Xếp Công Nghệ (Server Information Disclosure)',
          risk: 'Low',
          confidence: 'High',
          cweId: 'CWE-200',
          description: 'Máy chủ phản hồi tiết lộ tên và phiên bản của phần mềm nền tảng (ví dụ Express, Apache, NGINX). Tin tặc có thể dựa vào thông tin này để tra cứu CVE nhắm mục tiêu.',
          solution: 'Tắt hoặc ẩn các header này (ví dụ trong Express: app.disable("x-powered-by")).',
          url: targetUrl,
          method: 'GET',
          parameter: 'Response Headers',
          evidence: leaked
        });

        // Đối chiếu thành phần vừa lộ với cơ sở dữ liệu Exploit-DB
        const searchTarget = (headers['server'] || headers['x-powered-by'] || '').trim();
        if (searchTarget) {
          const edbMatches = await ExploitDbService.searchExploits(searchTarget, { limit: 3 });
          if (edbMatches.length > 0) {
            const firstEdb = edbMatches[0];
            const cves = firstEdb.cveList && firstEdb.cveList.length > 0 ? firstEdb.cveList.join(', ') : 'Chưa gán CVE';
            alerts.push({
              name: `Phát Hiện Mã Khai Thác Exploit-DB Cho Thành Phần (${searchTarget})`,
              risk: 'High',
              confidence: 'High',
              cweId: 'CWE-1395',
              description: `Hệ thống phát hiện thành phần "${searchTarget}" tồn tại ít nhất ${edbMatches.length} mã khai thác công khai (Public PoC) trên Exploit-DB: [EDB-ID: ${firstEdb.edbId}] ${firstEdb.description}. Kẻ tấn công có thể tải về script khai thác để tấn công ứng dụng.`,
              solution: `Cập nhật hoặc ẩn chữ ký phiên bản của ${searchTarget}. Tham khảo mã CVE liên quan: ${cves}.`,
              url: targetUrl,
              method: 'GET',
              parameter: 'Component Fingerprint',
              evidence: `Exploit-DB ID: ${firstEdb.edbId} - URL: ${firstEdb.url} - CVEs: ${cves}`
            });
          }
        }
      }

      // Test 2: Kiểm thử cấu hình sai CORS (CORS Misconfiguration / Origin Reflection)
      const corsRes = await client.get(targetUrl, {
        headers: { 'Origin': 'https://attacker-domain-malicious.com' }
      });

      const allowOrigin = corsRes.headers['access-control-allow-origin'];
      const allowCreds = corsRes.headers['access-control-allow-credentials'];

      if (allowOrigin === 'https://attacker-domain-malicious.com' && allowCreds === 'true') {
        alerts.push({
          name: 'Lỗ Hổng CORS Cực Kỳ Nghiêm Trọng (Arbitrary Origin Reflection with Credentials)',
          risk: 'High',
          confidence: 'High',
          cweId: 'CWE-942',
          description: 'Máy chủ chấp nhận và phản hồi bất kỳ Origin tùy ý nào gửi lên kèm theo chứng chỉ xác thực (Cookie / Bearer Token). Trang web độc hại có thể gửi request đánh cắp dữ liệu người dùng.',
          solution: 'Không bao giờ tin tưởng mù quáng Origin từ header của client. Thiết lập danh sách trắng (Whitelist) các domain được phép.',
          url: targetUrl,
          method: 'GET',
          parameter: 'Header: Origin',
          evidence: `Access-Control-Allow-Origin: ${allowOrigin}, Access-Control-Allow-Credentials: ${allowCreds}`
        });
      } else if (allowOrigin === '*') {
        alerts.push({
          name: 'CORS Mở Cho Toàn Bộ Internet (Wildcard Origin)',
          risk: 'Informational',
          confidence: 'Medium',
          cweId: 'CWE-942',
          description: 'Máy chủ cho phép mọi website truy cập API qua Access-Control-Allow-Origin: *. Nếu API chứa dữ liệu công khai thì bình thường, nhưng nếu chứa dữ liệu người dùng thì có thể rủi ro.',
          solution: 'Đảm bảo chỉ các API công khai mới dùng dấu *. Các API nhạy cảm cần hạn chế Origin.',
          url: targetUrl,
          method: 'GET',
          parameter: 'Access-Control-Allow-Origin',
          evidence: 'Access-Control-Allow-Origin: *'
        });
      }

      // Test 3: Kiểm thử phương thức HTTP nguy hiểm (HTTP Verb Tampering)
      const optionsRes = await client.options(targetUrl);
      const allowMethods = optionsRes.headers['allow'] || optionsRes.headers['access-control-allow-methods'] || '';
      if (allowMethods.toUpperCase().includes('TRACE')) {
        alerts.push({
          name: 'Bật Phương Thức HTTP TRACE (Nguy Cơ Cross-Site Tracing - XST)',
          risk: 'Medium',
          confidence: 'High',
          cweId: 'CWE-693',
          description: 'Phương thức TRACE cho phép gửi lại toàn bộ nội dung request bao gồm Cookie bảo vệ bởi HttpOnly, hỗ trợ tin tặc bẻ gãy phòng thủ XSS.',
          solution: 'Vô hiệu hóa phương thức TRACE trong cấu hình máy chủ web.',
          url: targetUrl,
          method: 'OPTIONS',
          parameter: 'HTTP Methods',
          evidence: `Allowed Methods: ${allowMethods}`
        });
      }

      // Test 4: Kiểm thử khả năng chịu lỗi & rò rỉ ngoại lệ (Error Handling & Stack Trace Leakage)
      const errorTestRes = await client.get(`${targetUrl}${targetUrl.includes('?') ? '&' : '?'}test_param_inject=%27%22%00%3Cscript%3E`);
      if (errorTestRes.status >= 500) {
        const bodyText = typeof errorTestRes.data === 'string' ? errorTestRes.data : JSON.stringify(errorTestRes.data || '');
        if (bodyText.includes('TypeError') || bodyText.includes('at ') || bodyText.includes('stack') || bodyText.includes('SQL')) {
          alerts.push({
            name: 'Rò Rỉ Dấu Vết Lỗi Hệ Thống (Stack Trace / Debug Leakage)',
            risk: 'High',
            confidence: 'Medium',
            cweId: 'CWE-209',
            description: 'Khi nhận tham số bất thường, máy chủ trả về mã lỗi 500 kèm chi tiết stack trace, đường dẫn thư mục hoặc câu lệnh cơ sở dữ liệu. Tin tặc có thể dùng thông tin này để xây dựng kịch bản khai thác sâu.',
            solution: 'Cấu hình xử lý lỗi tập trung (Global Error Handler), không bao giờ trả về stack trace cho client trong môi trường Production.',
            url: `${targetUrl}?test_param_inject=...`,
            method: 'GET',
            parameter: 'Query Parameter',
            evidence: `Status Code: ${errorTestRes.status}, Phát hiện nội dung debug trong phản hồi`
          });
        }
      }

    } catch (err) {
      alerts.push({
        name: 'Máy Chủ Mục Tiêu Không Thể Kết Nối',
        risk: 'Informational',
        confidence: 'Low',
        cweId: 'CWE-20',
        description: `Không thể kết nối đến URL mục tiêu: ${err.message}. Vui lòng kiểm tra ứng dụng có đang chạy hay không.`,
        solution: 'Khởi động ứng dụng trước khi tiến hành quét DAST.',
        url: targetUrl,
        method: 'GET',
        parameter: '',
        evidence: err.message
      });
    }

    const durationSeconds = Math.round((Date.now() - startTime) / 1000);
    const summary = this.calculateSummary(alerts);

    return {
      engineUsed: 'BUILTIN_DAST_ENGINE',
      summary,
      alerts,
      durationSeconds
    };
  }

  /**
   * Tính toán điểm số và cấp độ an ninh DAST (Grade A+ -> F)
   */
  static calculateSummary(alerts) {
    let high = 0;
    let medium = 0;
    let low = 0;
    let info = 0;

    for (const a of alerts) {
      if (a.risk === 'High') high++;
      else if (a.risk === 'Medium') medium++;
      else if (a.risk === 'Low') low++;
      else info++;
    }

    let grade = 'A+';
    let riskScore = 0;

    if (high > 0) {
      grade = high >= 2 ? 'F' : 'D';
      riskScore = Math.min(100, 80 + high * 10);
    } else if (medium > 0) {
      grade = medium >= 3 ? 'D' : 'C';
      riskScore = Math.min(79, 45 + medium * 10);
    } else if (low > 0) {
      grade = 'B';
      riskScore = Math.min(44, 20 + low * 5);
    } else {
      grade = info > 0 ? 'A' : 'A+';
      riskScore = 5;
    }

    return {
      totalAlerts: alerts.length,
      highRiskCount: high,
      mediumRiskCount: medium,
      lowRiskCount: low,
      infoCount: info,
      riskScore,
      grade
    };
  }

  /**
   * Chuẩn hóa mức độ rủi ro từ OWASP ZAP về chuẩn schema DastScan
   */
  static normalizeZapRisk(risk) {
    const val = (risk || '').toLowerCase();
    if (val === 'high') return 'High';
    if (val === 'medium') return 'Medium';
    if (val === 'low') return 'Low';
    return 'Informational';
  }

  /**
   * Thực thi quét DAST thực sự qua OWASP ZAP REST API (Spider -> Active Scan -> Alerts)
   */
  static async runZapDastAssessment(targetUrl) {
    const startTime = Date.now();
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      targetUrl = 'http://' + targetUrl;
    }

    const zapClient = axios.create({
      baseURL: this.ZAP_HOST,
      timeout: 10000,
      headers: this.ZAP_API_KEY ? { 'X-ZAP-API-Key': this.ZAP_API_KEY } : {}
    });

    // 1. Chạy ZAP Spider để thu thập các endpoint
    const spiderRes = await zapClient.get('/JSON/spider/action/scan/', {
      params: { url: targetUrl, maxChildren: 10, recurse: true }
    });
    const spiderScanId = spiderRes.data?.scan;
    if (spiderScanId === undefined || spiderScanId === null) {
      throw new Error('OWASP ZAP không trả về scanId cho Spider');
    }

    const spiderDeadline = Date.now() + 30000;
    while (Date.now() < spiderDeadline) {
      const statusRes = await zapClient.get('/JSON/spider/view/status/', {
        params: { scanId: spiderScanId }
      });
      if (parseInt(statusRes.data?.status, 10) >= 100) break;
      await new Promise((r) => setTimeout(r, 1000));
    }

    // 2. Chạy ZAP Active Scan
    const ascanRes = await zapClient.get('/JSON/ascan/action/scan/', {
      params: { url: targetUrl, recurse: true }
    });
    const ascanId = ascanRes.data?.scan;
    if (ascanId === undefined || ascanId === null) {
      throw new Error('OWASP ZAP không trả về scanId cho Active Scan');
    }

    const ascanDeadline = Date.now() + 45000;
    while (Date.now() < ascanDeadline) {
      const statusRes = await zapClient.get('/JSON/ascan/view/status/', {
        params: { scanId: ascanId }
      });
      if (parseInt(statusRes.data?.status, 10) >= 100) break;
      await new Promise((r) => setTimeout(r, 1500));
    }

    // 3. Thu thập kết quả Alerts từ OWASP ZAP
    const alertsRes = await zapClient.get('/JSON/core/view/alerts/', {
      params: { baseurl: targetUrl, start: 0, count: 100 }
    });
    const rawAlerts = Array.isArray(alertsRes.data?.alerts) ? alertsRes.data.alerts : [];

    const alerts = rawAlerts.map((a) => ({
      name: a.alert || a.name || 'ZAP Security Alert',
      risk: this.normalizeZapRisk(a.risk),
      confidence: a.confidence || 'Medium',
      cweId: a.cweid ? `CWE-${a.cweid}` : '',
      description: a.description || '',
      solution: a.solution || '',
      url: a.url || targetUrl,
      method: a.method || 'GET',
      parameter: a.param || '',
      evidence: a.evidence || '',
      reference: a.reference || ''
    }));

    const durationSeconds = Math.round((Date.now() - startTime) / 1000);
    const summary = this.calculateSummary(alerts);

    return {
      engineUsed: 'OWASP_ZAP_API',
      summary,
      alerts,
      durationSeconds
    };
  }

  /**
   * Tiến hành quét DAST: Tự động dùng OWASP ZAP API nếu có, hoặc dùng Built-in DAST Engine
   */
  static async scanEndpoint(targetUrl) {
    const zapStatus = await this.checkZapStatus();

    if (zapStatus.isAvailable) {
      try {
        console.log(`[+] Đang kích hoạt OWASP ZAP API quét: ${targetUrl}`);
        return await this.runZapDastAssessment(targetUrl);
      } catch (e) {
        console.warn('[-] Lỗi gọi ZAP, chuyển sang Built-in DAST Engine:', e.message);
      }
    }

    // Mặc định chạy Built-in Automated DAST Engine
    return await this.runBuiltinDastAssessment(targetUrl);
  }
}

module.exports = DastService;

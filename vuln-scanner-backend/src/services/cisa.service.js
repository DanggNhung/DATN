const axios = require('axios');
const cron = require('node-cron');
const CisaKev = require('../models/CisaKev.model');
const { CISA_KEV_URL } = require('../config/constants');

class CisaService {
  // In-memory set để tra cứu siêu nhanh O(1)
  static cisaCveSet = new Set();
  static isSyncing = false;
  static lastSynced = null;

  /**
   * Khởi tạo: Nạp CVEs từ DB vào RAM và lên lịch cron
   */
  static async init() {
    try {
      const count = await CisaKev.countDocuments();
      if (count === 0) {
        console.log('[*] Database CISA KEV đang trống, tiến hành đồng bộ lần đầu...');
        await this.syncCatalog();
      } else {
        await this.loadMemoryCache();
        console.log(`[+] Đã tải ${this.cisaCveSet.size} CVEs từ CISA KEV vào bộ nhớ cache.`);
      }

      // Lên lịch tự động đồng bộ mỗi 24 giờ vào lúc 03:00 sáng
      cron.schedule('0 3 * * *', async () => {
        console.log('[*] [CRON] Bắt đầu đồng bộ tự động CISA KEV Catalog...');
        await this.syncCatalog();
      });
    } catch (error) {
      console.error('[-] Lỗi khởi tạo CisaService:', error.message);
    }
  }

  /**
   * Nạp danh sách CVE IDs vào Set trong RAM
   */
  static async loadMemoryCache() {
    const records = await CisaKev.find({}, 'cveID').lean();
    this.cisaCveSet = new Set(records.map((r) => r.cveID.toUpperCase()));
    const latest = await CisaKev.findOne().sort({ updatedAt: -1 }).select('updatedAt');
    if (latest) {
      this.lastSynced = latest.updatedAt;
    }
  }

  /**
   * Tải toàn bộ catalog từ CISA và cập nhật vào MongoDB
   */
  static async syncCatalog() {
    if (this.isSyncing) {
      return { success: false, message: 'Đang trong tiến trình đồng bộ khác' };
    }

    this.isSyncing = true;
    console.log(`[*] Đang tải dữ liệu từ CISA: ${CISA_KEV_URL}`);

    try {
      const response = await axios.get(CISA_KEV_URL, { timeout: 30000 });
      const catalog = response.data;

      if (!catalog || !catalog.vulnerabilities || !Array.isArray(catalog.vulnerabilities)) {
        throw new Error('Dữ liệu CISA KEV không đúng định dạng');
      }

      const vulnerabilities = catalog.vulnerabilities;
      console.log(`[*] CISA cung cấp ${vulnerabilities.length} lỗ hổng. Đang lưu vào CSDL...`);

      // Sử dụng bulkWrite với upsert để cập nhật hoặc thêm mới
      const bulkOps = vulnerabilities.map((item) => ({
        updateOne: {
          filter: { cveID: item.cveID.toUpperCase() },
          update: {
            $set: {
              cveID: item.cveID.toUpperCase(),
              vendorProject: item.vendorProject || '',
              product: item.product || '',
              vulnerabilityName: item.vulnerabilityName || '',
              dateAdded: item.dateAdded || '',
              shortDescription: item.shortDescription || '',
              requiredAction: item.requiredAction || '',
              dueDate: item.dueDate || '',
              knownRansomwareCampaignUse: item.knownRansomwareCampaignUse || 'Unknown',
              notes: item.notes || '',
              lastSyncedAt: new Date()
            }
          },
          upsert: true
        }
      }));

      // Chạy theo từng batch 500 records để không làm nghẽn MongoDB
      const batchSize = 500;
      for (let i = 0; i < bulkOps.length; i += batchSize) {
        const batch = bulkOps.slice(i, i + batchSize);
        await CisaKev.bulkWrite(batch);
      }

      await this.loadMemoryCache();
      this.lastSynced = new Date();
      console.log(`[+] Đồng bộ thành công ${vulnerabilities.length} CVEs từ CISA KEV Catalog!`);

      return {
        success: true,
        count: vulnerabilities.length,
        catalogVersion: catalog.catalogVersion,
        dateReleased: catalog.dateReleased,
        lastSynced: this.lastSynced
      };
    } catch (error) {
      console.error('[-] Lỗi đồng bộ CISA KEV:', error.message);
      return { success: false, error: error.message };
    } finally {
      this.isSyncing = false;
    }
  }

  /**
   * Kiểm tra nhanh một danh sách mã CVE/GHSA có thuộc CISA KEV không
   * @param {string[]} cveList - Mảng các mã CVE
   * @returns {Promise<Map<string, Object>>}
   */
  static async checkVulnerabilities(cveList) {
    if (!cveList || cveList.length === 0) return new Map();

    // Lọc các mã có trong RAM cache
    const matchedCves = cveList
      .map((c) => c.toUpperCase())
      .filter((c) => this.cisaCveSet.has(c));

    if (matchedCves.length === 0) return new Map();

    // Lấy chi tiết từ DB
    const details = await CisaKev.find({ cveID: { $in: matchedCves } }).lean();
    const map = new Map();
    for (const item of details) {
      map.set(item.cveID.toUpperCase(), item);
    }
    return map;
  }

  /**
   * Lấy thống kê CISA
   */
  static async getStats() {
    const count = await CisaKev.countDocuments();
    return {
      totalKevVulnerabilities: count,
      inMemoryCached: this.cisaCveSet.size,
      lastSynced: this.lastSynced,
      isSyncing: this.isSyncing
    };
  }
}

module.exports = CisaService;

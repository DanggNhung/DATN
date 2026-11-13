require('dotenv').config();

module.exports = {
  PORT: process.env.PORT || 5000,
  MONGODB_URI: process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/vuln_scanner_db',
  JWT_SECRET: process.env.JWT_SECRET || 'devsecops_jwt_secret_key_default',
  // OSV (Open Source Vulnerabilities) API của Google - tra cứu miễn phí, không cần key
  OSV_API_URL: process.env.OSV_API_URL || 'https://api.osv.dev/v1/query',
  OSV_BATCH_URL: process.env.OSV_BATCH_URL || 'https://api.osv.dev/v1/querybatch',
  
  // Danh mục Known Exploited Vulnerabilities (KEV) của CISA (dùng mirror chính thức của CISA trên GitHub tránh chặn Akamai 403)
  CISA_KEV_URL: process.env.CISA_KEV_URL || 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json'
};
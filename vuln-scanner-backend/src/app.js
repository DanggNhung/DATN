require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const connectDB = require('./config/db');
const { PORT } = require('./config/constants');
const CisaService = require('./services/cisa.service');
const ExploitDbService = require('./services/exploitdb.service');

const scanRoutes = require('./routes/scan.route');
const authRoutes = require('./routes/auth.route');
const adminRoutes = require('./routes/admin.route');
const dastRoutes = require('./routes/dast.route');
const exploitDbRoutes = require('./routes/exploitdb.route');

const app = express();

// Ẩn header X-Powered-By: Express để tránh lộ ngăn xếp công nghệ (CWE-200)
app.disable('x-powered-by');

// Khởi tạo kết nối MongoDB
connectDB().then(() => {
  // Sau khi kết nối DB, nạp dữ liệu CISA KEV & Exploit-DB
  CisaService.init();
  ExploitDbService.init();
});

// Đảm bảo thư mục uploads tồn tại khi khởi chạy
const uploadsDir = path.join(__dirname, '../uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Security Headers Middleware (CSP, X-Content-Type-Options, X-Frame-Options, HSTS)
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none';");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.removeHeader('X-Powered-By');
  next();
});

// Cấu hình CORS Whitelist (tránh sử dụng Access-Control-Allow-Origin: * - CWE-942)
const envOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      // Cho phép request không có Origin (Postman, curl, VS Code Extension, server-to-server)
      if (!origin) return callback(null, true);

      const isLocalhost = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(origin);
      const isVercelPreview = /^https:\/\/[a-z0-9-]+\.vercel\.app$/i.test(origin);
      const isWhitelisted = envOrigins.includes(origin);

      if (isWhitelisted || isLocalhost || isVercelPreview) {
        return callback(null, true);
      }
      return callback(new Error('Origin không nằm trong danh sách CORS cho phép'));
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key']
  })
);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Đăng ký routes
app.use('/api/v1/scan', scanRoutes);
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/admin', adminRoutes);
app.use('/api/v1/dast', dastRoutes);
app.use('/api/v1/exploitdb', exploitDbRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'UP',
    message: 'DevSecOps SCA Scanner & CISA KEV Engine is operational',
    timestamp: new Date().toISOString()
  });
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Endpoint không tồn tại' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('[-] Server Error:', err);
  res.status(500).json({ success: false, error: err.message || 'Lỗi máy chủ nội bộ' });
});

app.listen(PORT, () => {
  console.log(`[+] Server SCA Scanner đang chạy tại: http://localhost:${PORT}`);
});
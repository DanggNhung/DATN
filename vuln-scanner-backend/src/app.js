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

// Middleware
app.use(cors());
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
const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const scanController = require('../controllers/scan.controller');
const { optionalAuth, verifyAuth } = require('../middlewares/auth.middleware');

// Cấu hình lưu file upload tạm thời
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, '../../uploads'));
  },
  filename: (req, file, cb) => {
    try {
      file.originalname = Buffer.from(file.originalname, 'latin1').toString('utf8');
    } catch (e) {}
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const safeExt = path.extname(file.originalname);
    cb(null, uniqueSuffix + safeExt);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 25 * 1024 * 1024 } // Hỗ trợ tệp nén tới 25MB
});

// Thống kê công khai
router.get('/public/stats', scanController.getPublicStats);

// Lịch sử quét của người dùng
router.get('/history', verifyAuth, scanController.getScanHistory);

// Chi tiết 1 bài quét theo ID
router.get('/:id', optionalAuth, scanController.getScanById);

// Tiếp nhận upload file quét
router.post('/upload', optionalAuth, upload.single('file'), scanController.scanFile);

// Tiếp nhận quét trực tiếp qua raw content (cho Extension)
router.post('/raw', optionalAuth, scanController.scanRaw);

module.exports = router;
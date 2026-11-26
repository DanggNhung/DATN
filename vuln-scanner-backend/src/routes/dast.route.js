const express = require('express');
const router = express.Router();
const dastController = require('../controllers/dast.controller');
const { optionalAuth, verifyAuth } = require('../middlewares/auth.middleware');

// Kiểm tra tình trạng kết nối OWASP ZAP
router.get('/zap-status', dastController.getZapStatus);

// Lịch sử kiểm thử DAST
router.get('/history', verifyAuth, dastController.getDastHistory);

// Chi tiết bài kiểm thử DAST theo ID (bắt buộc đăng nhập)
router.get('/:id', verifyAuth, dastController.getDastById);

// Nhận quyền sở hữu và xem kết quả DAST khách vừa test sau khi đăng nhập
router.post('/:id/claim', verifyAuth, dastController.claimDastScan);

// Khởi động kiểm thử DAST
router.post('/scan', optionalAuth, dastController.startDastScan);

module.exports = router;

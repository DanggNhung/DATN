const express = require('express');
const router = express.Router();
const adminController = require('../controllers/admin.controller');
const { verifyAuth, isAdmin } = require('../middlewares/auth.middleware');

// Mọi route admin đều yêu cầu đã đăng nhập và có role admin
router.use(verifyAuth, isAdmin);

// Quản lý người dùng
router.get('/users', adminController.getUsers);
router.patch('/users/:userId/status', adminController.toggleUserStatus);
router.patch('/users/:userId/role', adminController.updateUserRole);

// Quản lý đồng bộ dữ liệu CISA KEV
router.post('/cisa/sync', adminController.triggerCisaSync);
router.get('/cisa/status', adminController.getCisaStatus);

// Thống kê tổng quan Admin
router.get('/overview', adminController.getAdminOverview);

module.exports = router;

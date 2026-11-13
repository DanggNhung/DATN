const jwt = require('jsonwebtoken');
const User = require('../models/User.model');
const { JWT_SECRET } = require('../config/constants');

/**
 * Middleware xác thực: Hỗ trợ cả JWT Bearer Token (trên Web) và X-API-KEY (trên VS Code Extension)
 */
exports.verifyAuth = async (req, res, next) => {
  try {
    let token = null;
    const authHeader = req.headers.authorization;
    const apiKey = req.headers['x-api-key'];

    // 1. Kiểm tra API Key từ Header
    if (apiKey) {
      const user = await User.findOne({ apiKey, isActive: true });
      if (!user) {
        return res.status(401).json({ success: false, error: 'API Key không hợp lệ hoặc tài khoản đã bị khóa' });
      }
      req.user = user;
      return next();
    }

    // 2. Kiểm tra JWT Bearer Token
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({ success: false, error: 'Vui lòng đăng nhập hoặc cung cấp API Key' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user || !user.isActive) {
      return res.status(401).json({ success: false, error: 'Người dùng không tồn tại hoặc tài khoản đã bị khóa' });
    }

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, error: 'Phiên đăng nhập đã hết hạn hoặc không hợp lệ' });
  }
};

/**
 * Middleware cho phép khách (Anonymous) hoặc người dùng đã đăng nhập
 */
exports.optionalAuth = async (req, res, next) => {
  try {
    let token = null;
    const authHeader = req.headers.authorization;
    const apiKey = req.headers['x-api-key'];

    if (apiKey) {
      const user = await User.findOne({ apiKey, isActive: true });
      if (user) req.user = user;
      return next();
    }

    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.id);
      if (user && user.isActive) {
        req.user = user;
      }
    }
  } catch (err) {
    // Bỏ qua lỗi nếu là optional
  }
  next();
};

/**
 * Middleware kiểm tra quyền Quản trị viên (Admin)
 */
exports.isAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ success: false, error: 'Bạn không có quyền truy cập chức năng Quản trị' });
  }
  next();
};

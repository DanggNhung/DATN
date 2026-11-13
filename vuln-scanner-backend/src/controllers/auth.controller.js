const jwt = require('jsonwebtoken');
const User = require('../models/User.model');
const { JWT_SECRET } = require('../config/constants');

// Tạo JWT Token (hạn 7 ngày)
const generateToken = (userId) => {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '7d' });
};

/**
 * Đăng ký tài khoản
 */
exports.register = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ success: false, error: 'Vui lòng điền đầy đủ username, email và password' });
    }

    // Kiểm tra xem username hoặc email đã tồn tại chưa
    const existingUser = await User.findOne({
      $or: [{ email: email.toLowerCase() }, { username: username.trim() }]
    });

    if (existingUser) {
      return res.status(400).json({ success: false, error: 'Email hoặc tên người dùng đã tồn tại' });
    }

    // Nếu là tài khoản đầu tiên trong hệ thống, tự động cấp quyền Admin
    const userCount = await User.countDocuments();
    const role = userCount === 0 ? 'admin' : 'user';

    const user = await User.create({
      username: username.trim(),
      email: email.toLowerCase().trim(),
      password,
      role
    });

    const token = generateToken(user._id);

    return res.status(201).json({
      success: true,
      message: 'Đăng ký tài khoản thành công',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        apiKey: user.apiKey
      }
    });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};

/**
 * Đăng nhập
 */
exports.login = async (req, res) => {
  try {
    const { emailOrUsername, password } = req.body;

    if (!emailOrUsername || !password) {
      return res.status(400).json({ success: false, error: 'Vui lòng cung cấp email/username và mật khẩu' });
    }

    const user = await User.findOne({
      $or: [{ email: emailOrUsername.toLowerCase() }, { username: emailOrUsername }]
    }).select('+password');

    if (!user) {
      return res.status(401).json({ success: false, error: 'Tài khoản hoặc mật khẩu không chính xác' });
    }

    if (!user.isActive) {
      return res.status(403).json({ success: false, error: 'Tài khoản của bạn đã bị vô hiệu hóa bởi Quản trị viên' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ success: false, error: 'Tài khoản hoặc mật khẩu không chính xác' });
    }

    const token = generateToken(user._id);

    return res.json({
      success: true,
      message: 'Đăng nhập thành công',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        apiKey: user.apiKey
      }
    });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};

/**
 * Lấy thông tin tài khoản hiện tại
 */
exports.getMe = async (req, res) => {
  return res.json({
    success: true,
    user: {
      id: req.user._id,
      username: req.user.username,
      email: req.user.email,
      role: req.user.role,
      apiKey: req.user.apiKey,
      createdAt: req.user.createdAt
    }
  });
};

/**
 * Làm mới API Key cho người dùng
 */
exports.regenerateApiKey = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    const newKey = user.regenerateApiKey();
    await user.save();

    return res.json({
      success: true,
      message: 'Đã tạo mới API Key thành công',
      apiKey: newKey
    });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};

const User = require('../models/User.model');
const Scan = require('../models/Scan.model');
const CisaKev = require('../models/CisaKev.model');
const CisaService = require('../services/cisa.service');
const ExploitDbService = require('../services/exploitdb.service');

/**
 * Lấy danh sách người dùng (hỗ trợ phân trang và tìm kiếm)
 */
exports.getUsers = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const search = req.query.search || '';

    const query = {};
    if (search) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }

    const total = await User.countDocuments(query);
    const users = await User.find(query)
      .select('-__v')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    return res.json({
      success: true,
      data: users,
      pagination: {
        total,
        page,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};

/**
 * Khóa hoặc Mở khóa tài khoản người dùng
 */
exports.toggleUserStatus = async (req, res) => {
  try {
    const { userId } = req.params;

    if (req.user._id.toString() === userId) {
      return res.status(400).json({ success: false, error: 'Không thể tự khóa tài khoản của chính mình' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, error: 'Không tìm thấy người dùng' });
    }

    user.isActive = !user.isActive;
    await user.save();

    return res.json({
      success: true,
      message: `Đã ${user.isActive ? 'mở khóa' : 'khóa'} tài khoản thành công`,
      user: {
        id: user._id,
        username: user.username,
        isActive: user.isActive
      }
    });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};

/**
 * Đổi phân quyền người dùng (User <-> Admin)
 */
exports.updateUserRole = async (req, res) => {
  try {
    const { userId } = req.params;
    const { role } = req.body;

    if (!['user', 'admin'].includes(role)) {
      return res.status(400).json({ success: false, error: 'Vai trò không hợp lệ (user hoặc admin)' });
    }

    if (req.user._id.toString() === userId && role !== 'admin') {
      return res.status(400).json({ success: false, error: 'Không thể tự hạ quyền Admin của chính mình' });
    }

    const user = await User.findByIdAndUpdate(userId, { role }, { new: true });
    if (!user) {
      return res.status(404).json({ success: false, error: 'Không tìm thấy người dùng' });
    }

    return res.json({
      success: true,
      message: `Đã cập nhật vai trò thành ${role}`,
      user: {
        id: user._id,
        username: user.username,
        role: user.role
      }
    });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};

/**
 * Trigger đồng bộ dữ liệu CISA KEV thủ công
 */
exports.triggerCisaSync = async (req, res) => {
  try {
    const syncResult = await CisaService.syncCatalog();
    return res.json({
      success: true,
      message: 'Đã hoàn tất tiến trình đồng bộ CISA KEV',
      details: syncResult
    });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};

/**
 * Lấy trạng thái CISA KEV
 */
exports.getCisaStatus = async (req, res) => {
  try {
    const stats = await CisaService.getStats();
    return res.json({ success: true, stats });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};

/**
 * Thống kê tổng quan cho Admin Dashboard
 */
exports.getAdminOverview = async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalScans = await Scan.countDocuments();
    const cisaStats = await CisaService.getStats();
    const exploitDbStats = await ExploitDbService.getStats();

    // Thống kê phân loại rủi ro
    const riskStats = await Scan.aggregate([
      {
        $group: {
          _id: '$summary.riskLevel',
          count: { $sum: 1 }
        }
      }
    ]);

    // Top các gói thư viện dính nhiều lỗ hổng nhất
    const recentScans = await Scan.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .select('projectName fileName summary createdAt source')
      .populate('userId', 'username email');

    return res.json({
      success: true,
      overview: {
        totalUsers,
        totalScans,
        cisaKevCatalogCount: cisaStats.totalKevVulnerabilities,
        cisaLastSynced: cisaStats.lastSynced,
        exploitDbCount: exploitDbStats.totalExploits,
        exploitDbMappedCves: exploitDbStats.mappedCves,
        exploitDbLastSynced: exploitDbStats.lastSynced,
        riskDistribution: riskStats,
        recentScans
      }
    });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};

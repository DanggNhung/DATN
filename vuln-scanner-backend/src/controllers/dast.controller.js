const DastService = require('../services/dast.service');
const DastScan = require('../models/DastScan.model');

/**
 * Bắt đầu quét kiểm thử động API (DAST)
 */
exports.startDastScan = async (req, res) => {
  try {
    const { targetUrl, projectName } = req.body;

    if (!targetUrl || typeof targetUrl !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Vui lòng cung cấp targetUrl (địa chỉ URL của API / Ứng dụng cần kiểm thử)'
      });
    }

    const cleanTargetUrl = targetUrl.trim();
    const cleanProjectName = projectName ? projectName.trim() : 'API Security Test';

    // Thực hiện quét DAST
    const scanResult = await DastService.scanEndpoint(cleanTargetUrl);

    // Lưu vào CSDL
    const dastRecord = await DastScan.create({
      userId: req.user ? req.user._id : null,
      projectName: cleanProjectName,
      targetUrl: cleanTargetUrl,
      engineUsed: scanResult.engineUsed,
      status: 'completed',
      summary: scanResult.summary,
      alerts: scanResult.alerts,
      durationSeconds: scanResult.durationSeconds
    });

    // Khách chưa đăng nhập chỉ được test URL, buộc đăng nhập mới được xem kết quả chi tiết
    if (!req.user) {
      return res.json({
        success: true,
        requiresAuth: true,
        scanId: dastRecord._id,
        scannedAt: dastRecord.createdAt,
        projectName: dastRecord.projectName,
        targetUrl: dastRecord.targetUrl,
        message: 'Đã hoàn tất kiểm thử DAST. Vui lòng đăng nhập để xem kết quả chi tiết.'
      });
    }

    return res.json({
      success: true,
      scanId: dastRecord._id,
      scannedAt: dastRecord.createdAt,
      projectName: dastRecord.projectName,
      targetUrl: dastRecord.targetUrl,
      engineUsed: dastRecord.engineUsed,
      summary: dastRecord.summary,
      alerts: dastRecord.alerts,
      durationSeconds: dastRecord.durationSeconds
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: 'Lỗi trong quá trình kiểm thử DAST: ' + error.message
    });
  }
};

/**
 * Lấy lịch sử quét DAST
 */
exports.getDastHistory = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;

    const query = {};
    if (req.user && req.user.role !== 'admin') {
      query.userId = req.user._id;
    }

    const total = await DastScan.countDocuments(query);
    const scans = await DastScan.find(query)
      .select('projectName targetUrl engineUsed summary status createdAt durationSeconds')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    return res.json({
      success: true,
      data: scans,
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
 * Lấy chi tiết bài kiểm thử DAST (bắt buộc đăng nhập)
 */
exports.getDastById = async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ success: false, error: 'Vui lòng đăng nhập để xem kết quả kiểm thử DAST' });
    }

    const { id } = req.params;
    const scan = await DastScan.findById(id).populate('userId', 'username email');

    if (!scan) {
      return res.status(404).json({ success: false, error: 'Không tìm thấy kết quả kiểm thử DAST' });
    }

    // Kiểm tra quyền truy cập: Chặn người dùng khác khi dữ liệu có chủ sở hữu
    if (scan.userId) {
      const ownerId = (scan.userId._id || scan.userId).toString();
      const isOwner = req.user._id && req.user._id.toString() === ownerId;
      const isAdmin = req.user.role === 'admin';

      if (!isOwner && !isAdmin) {
        return res.status(403).json({ success: false, error: 'Bạn không có quyền xem kết quả này' });
      }
    }

    return res.json({
      success: true,
      data: scan
    });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};

/**
 * Nhận quyền sở hữu bài kiểm thử DAST khách vừa test sau khi đăng nhập
 */
exports.claimDastScan = async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ success: false, error: 'Vui lòng đăng nhập để xem kết quả kiểm thử DAST' });
    }

    const { id } = req.params;
    const scan = await DastScan.findById(id);

    if (!scan) {
      return res.status(404).json({ success: false, error: 'Không tìm thấy kết quả kiểm thử DAST' });
    }

    if (scan.userId) {
      const ownerId = scan.userId.toString();
      const isOwner = req.user._id && req.user._id.toString() === ownerId;
      const isAdmin = req.user.role === 'admin';
      if (!isOwner && !isAdmin) {
        return res.status(403).json({ success: false, error: 'Bạn không có quyền xem kết quả này' });
      }
    } else {
      scan.userId = req.user._id;
      await scan.save();
    }

    return res.json({
      success: true,
      data: scan
    });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};

/**
 * Kiểm tra trạng thái kết nối với OWASP ZAP Daemon
 */
exports.getZapStatus = async (req, res) => {
  try {
    const status = await DastService.checkZapStatus();
    return res.json({ success: true, status });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};

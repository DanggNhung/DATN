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
 * Lấy chi tiết bài kiểm thử DAST
 */
exports.getDastById = async (req, res) => {
  try {
    const { id } = req.params;
    const scan = await DastScan.findById(id).populate('userId', 'username email');

    if (!scan) {
      return res.status(404).json({ success: false, error: 'Không tìm thấy kết quả kiểm thử DAST' });
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

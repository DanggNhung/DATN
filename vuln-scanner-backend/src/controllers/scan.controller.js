const fs = require('fs');
const path = require('path');
const ParserService = require('../services/parser.service');
const ScannerService = require('../services/scanner.service');
const Scan = require('../models/Scan.model');

/**
 * Xử lý an toàn chuỗi tiếng Việt bị lỗi mã hóa UTF-8 do Multer/Busboy (mojibake latin1)
 */
function decodeUtf8Safe(str) {
  if (!str || typeof str !== 'string') return str;
  try {
    const converted = Buffer.from(str, 'latin1').toString('utf8');
    if (!converted.includes('\ufffd') && converted !== str) {
      return converted;
    }
  } catch (e) {}
  return str;
}

/**
 * Quét thông qua upload tệp (package.json, requirements.txt, .zip)
 */
exports.scanFile = async (req, res) => {
  let uploadedFilePath = null;

  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'Vui lòng đính kèm tệp để quét' });
    }

    uploadedFilePath = req.file.path;
    const cleanFileName = decodeUtf8Safe(req.file.originalname);
    const originalNameLower = cleanFileName.toLowerCase();
    const cleanProjectName = req.body.projectName
      ? decodeUtf8Safe(req.body.projectName)
      : cleanFileName.replace(/\.[^/.]+$/, '');

    let packages = [];
    let detectedFileType = 'unknown';

    // 1. Phân loại và bóc tách định dạng tệp
    if (originalNameLower === 'package.json') {
      detectedFileType = 'npm';
      packages = ParserService.parsePackageJson(uploadedFilePath);
    } else if (originalNameLower.endsWith('.txt')) {
      detectedFileType = 'pypi';
      packages = ParserService.parseRequirementsTxt(uploadedFilePath);
    } else if (originalNameLower.endsWith('.zip')) {
      const zipResult = ParserService.parseZipFile(uploadedFilePath);
      detectedFileType = zipResult.fileType;
      packages = zipResult.packages;
    } else {
      if (fs.existsSync(uploadedFilePath)) fs.unlinkSync(uploadedFilePath);
      return res.status(400).json({
        success: false,
        error: 'Định dạng chưa hỗ trợ. Vui lòng tải lên package.json, requirements.txt hoặc file nén .zip'
      });
    }

    if (packages.length === 0) {
      if (fs.existsSync(uploadedFilePath)) fs.unlinkSync(uploadedFilePath);
      return res.status(400).json({
        success: false,
        error: 'Không tìm thấy thông tin gói thư viện nào trong tệp đã tải lên'
      });
    }

    // 2. Thực hiện quét danh sách thư viện qua OSV và đối chiếu CISA KEV
    const results = await ScannerService.scanDependencies(packages);

    // 3. Tính toán các chỉ số thống kê & mức độ rủi ro (AUD-01: Phân biệt rõ an toàn vs lỗi kiểm tra)
    const vulnerableCount = results.filter((item) => item.isVulnerable).length;
    const safeCount = results.filter((item) => item.isSafe).length;
    const errorCount = results.filter((item) => item.hasScanError || item.scanStatus === 'error').length;
    const riskAnalysis = ScannerService.calculateRisk(results);

    // Xóa file tạm sau khi đã xử lý
    if (fs.existsSync(uploadedFilePath)) {
      fs.unlinkSync(uploadedFilePath);
      uploadedFilePath = null;
    }

    // Xác định trạng thái quét tổng quát
    let scanStatus = 'completed';
    if (errorCount > 0) {
      scanStatus = errorCount === packages.length ? 'failed' : 'partial';
    }

    // 4. Lưu kết quả vào MongoDB
    const scanRecord = await Scan.create({
      userId: req.user ? req.user._id : null,
      projectName: cleanProjectName,
      fileName: cleanFileName,
      fileType: detectedFileType,
      source: req.headers['x-api-key'] ? 'vscode_extension' : 'web',
      summary: {
        totalPackages: packages.length,
        vulnerablePackages: vulnerableCount,
        safePackages: safeCount,
        errorPackages: errorCount,
        hasScanErrors: errorCount > 0,
        cisaKevCount: riskAnalysis.cisaKevCount,
        riskScore: riskAnalysis.riskScore,
        riskLevel: riskAnalysis.riskLevel
      },
      results: results,
      status: scanStatus
    });

    return res.json({
      success: true,
      scanId: scanRecord._id,
      scannedAt: scanRecord.createdAt,
      projectName: scanRecord.projectName,
      fileName: scanRecord.fileName,
      fileType: scanRecord.fileType,
      summary: scanRecord.summary,
      results: scanRecord.results
    });
  } catch (err) {
    if (uploadedFilePath && fs.existsSync(uploadedFilePath)) {
      fs.unlinkSync(uploadedFilePath);
    }

    return res.status(500).json({
      success: false,
      error: 'Lỗi trong quá trình quét tệp: ' + err.message
    });
  }
};

/**
 * Quét trực tiếp qua raw content (Dành cho VS Code Extension hoặc CLI)
 */
exports.scanRaw = async (req, res) => {
  try {
    const { content, ecosystem, projectName, filename } = req.body;

    if (!content || !ecosystem) {
      return res.status(400).json({
        success: false,
        error: 'Vui lòng cung cấp content (nội dung file) và ecosystem (npm hoặc PyPI)'
      });
    }

    let packages = [];
    let detectedType = 'unknown';

    if (ecosystem.toLowerCase() === 'npm') {
      detectedType = 'npm';
      packages = ParserService.parsePackageJsonContent(content);
    } else if (ecosystem.toLowerCase() === 'pypi') {
      detectedType = 'pypi';
      packages = ParserService.parseRequirementsTxtContent(content);
    } else {
      return res.status(400).json({ success: false, error: 'Ecosystem chỉ hỗ trợ: npm hoặc PyPI' });
    }

    if (packages.length === 0) {
      return res.status(400).json({ success: false, error: 'Không tìm thấy thư viện hợp lệ nào để quét' });
    }

    // Quét thư viện
    const results = await ScannerService.scanDependencies(packages);
    const vulnerableCount = results.filter((item) => item.isVulnerable).length;
    const safeCount = results.filter((item) => item.isSafe).length;
    const errorCount = results.filter((item) => item.hasScanError || item.scanStatus === 'error').length;
    const riskAnalysis = ScannerService.calculateRisk(results);

    let scanStatus = 'completed';
    if (errorCount > 0) {
      scanStatus = errorCount === packages.length ? 'failed' : 'partial';
    }

    // Lưu vào CSDL
    const scanRecord = await Scan.create({
      userId: req.user ? req.user._id : null,
      projectName: projectName || 'VS Code Workspace',
      fileName: filename || (ecosystem === 'npm' ? 'package.json' : 'requirements.txt'),
      fileType: detectedType,
      source: 'vscode_extension',
      summary: {
        totalPackages: packages.length,
        vulnerablePackages: vulnerableCount,
        safePackages: safeCount,
        errorPackages: errorCount,
        hasScanErrors: errorCount > 0,
        cisaKevCount: riskAnalysis.cisaKevCount,
        riskScore: riskAnalysis.riskScore,
        riskLevel: riskAnalysis.riskLevel
      },
      results: results,
      status: scanStatus
    });

    return res.json({
      success: true,
      scanId: scanRecord._id,
      scannedAt: scanRecord.createdAt,
      projectName: scanRecord.projectName,
      fileName: scanRecord.fileName,
      fileType: scanRecord.fileType,
      summary: scanRecord.summary,
      results: scanRecord.results
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: 'Lỗi trong quá trình quét: ' + err.message
    });
  }
};

/**
 * Lấy lịch sử quét của người dùng
 */
exports.getScanHistory = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;

    const query = {};
    // Nếu là user bình thường thì chỉ xem được bài quét của chính mình
    if (req.user && req.user.role !== 'admin') {
      query.userId = req.user._id;
    } else if (req.query.userId) {
      query.userId = req.query.userId;
    }

    const total = await Scan.countDocuments(query);
    const rawScans = await Scan.find(query)
      .select('projectName fileName fileType source summary status createdAt')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();

    const scans = rawScans.map((s) => ({
      ...s,
      projectName: decodeUtf8Safe(s.projectName),
      fileName: decodeUtf8Safe(s.fileName)
    }));

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
 * Lấy chi tiết một bài quét theo ID
 */
exports.getScanById = async (req, res) => {
  try {
    const { id } = req.params;
    const scan = await Scan.findById(id).populate('userId', 'username email').lean();

    if (!scan) {
      return res.status(404).json({ success: false, error: 'Không tìm thấy kết quả quét' });
    }

    // Nếu bài quét thuộc về user khác và người gọi không phải admin
    if (scan.userId && req.user && req.user.role !== 'admin' && scan.userId._id.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, error: 'Bạn không có quyền xem kết quả này' });
    }

    scan.projectName = decodeUtf8Safe(scan.projectName);
    scan.fileName = decodeUtf8Safe(scan.fileName);

    return res.json({
      success: true,
      data: scan
    });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};

/**
 * Lấy thống kê công khai cho trang chủ
 */
exports.getPublicStats = async (req, res) => {
  try {
    const totalScans = await Scan.countDocuments();
    const statsAgg = await Scan.aggregate([
      {
        $group: {
          _id: null,
          totalPackagesScanned: { $sum: '$summary.totalPackages' },
          totalVulnerablePackages: { $sum: '$summary.vulnerablePackages' },
          totalCisaKevFound: { $sum: '$summary.cisaKevCount' }
        }
      }
    ]);

    const stats = statsAgg[0] || {
      totalPackagesScanned: 0,
      totalVulnerablePackages: 0,
      totalCisaKevFound: 0
    };

    return res.json({
      success: true,
      stats: {
        totalScans,
        totalPackagesScanned: stats.totalPackagesScanned,
        totalVulnerablePackages: stats.totalVulnerablePackages,
        totalCisaKevFound: stats.totalCisaKevFound
      }
    });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};
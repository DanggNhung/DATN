const mongoose = require('mongoose');

const vulnerabilityDetailSchema = new mongoose.Schema(
  {
    id: { type: String, required: true }, // CVE hoặc GHSA
    aliases: [{ type: String }],          // Các mã CVE tương đương
    summary: { type: String, default: '' },
    details: { type: String, default: '' },
    severity: { type: String, default: 'UNKNOWN' },
    isCisaKev: { type: Boolean, default: false },
    cisaKevDetails: {
      vulnerabilityName: String,
      dateAdded: String,
      requiredAction: String,
      knownRansomwareCampaignUse: String
    },
    fixed: { type: String, default: null }, // Phiên bản đã vá
    references: [{ type: String }]
  },
  { _id: false }
);

const packageResultSchema = new mongoose.Schema(
  {
    package: { type: String, required: true },
    version: { type: String, required: true },
    ecosystem: { type: String, required: true },
    isVulnerable: { type: Boolean, default: false },
    isSafe: { type: Boolean, default: false },
    hasScanError: { type: Boolean, default: false },
    scanStatus: {
      type: String,
      enum: ['scanned', 'error', 'partial'],
      default: 'scanned'
    },
    scanError: { type: String, default: null },
    sources: {
      osv: {
        status: { type: String, default: 'pending' },
        error: { type: String, default: null }
      },
      cisaKev: {
        status: { type: String, default: 'pending' },
        error: { type: String, default: null }
      },
      exploitDb: {
        status: { type: String, default: 'pending' },
        error: { type: String, default: null }
      }
    },
    hasCisaKev: { type: Boolean, default: false },
    hasExploitDb: { type: Boolean, default: false },
    totalVulnerabilities: { type: Number, default: 0 },
    fixedVersion: { type: String, default: null }, // Khuyến nghị phiên bản an toàn
    vulnerabilities: [vulnerabilityDetailSchema]
  },
  { _id: false }
);

const scanSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null
    },
    projectName: {
      type: String,
      default: 'Unnamed Project'
    },
    fileName: {
      type: String,
      required: true
    },
    fileType: {
      type: String,
      enum: ['npm', 'pypi', 'zip', 'unknown'],
      default: 'unknown'
    },
    source: {
      type: String,
      enum: ['web', 'vscode_extension', 'api'],
      default: 'web'
    },
    summary: {
      totalPackages: { type: Number, default: 0 },
      vulnerablePackages: { type: Number, default: 0 },
      safePackages: { type: Number, default: 0 },
      errorPackages: { type: Number, default: 0 },
      hasScanErrors: { type: Boolean, default: false },
      cisaKevCount: { type: Number, default: 0 },
      riskScore: { type: Number, default: 0 }, // 0 - 100
      riskLevel: {
        type: String,
        enum: ['SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INCONCLUSIVE'],
        default: 'SAFE'
      }
    },
    results: [packageResultSchema],
    status: {
      type: String,
      enum: ['pending', 'completed', 'partial', 'failed'],
      default: 'completed'
    }
  },
  {
    timestamps: true
  }
);

// Index cho truy vấn lịch sử nhanh
scanSchema.index({ userId: 1, createdAt: -1 });

module.exports = mongoose.model('Scan', scanSchema);

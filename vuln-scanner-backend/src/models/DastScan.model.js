const mongoose = require('mongoose');

const dastAlertSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    risk: {
      type: String,
      enum: ['High', 'Medium', 'Low', 'Informational'],
      default: 'Low'
    },
    confidence: { type: String, default: 'Medium' },
    cweId: { type: String, default: '' },
    description: { type: String, default: '' },
    solution: { type: String, default: '' },
    url: { type: String, default: '' },
    method: { type: String, default: 'GET' },
    parameter: { type: String, default: '' },
    evidence: { type: String, default: '' },
    reference: { type: String, default: '' }
  },
  { _id: false }
);

const dastScanSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null
    },
    projectName: {
      type: String,
      default: 'API Security Assessment'
    },
    targetUrl: {
      type: String,
      required: true
    },
    engineUsed: {
      type: String,
      enum: ['OWASP_ZAP_API', 'BUILTIN_DAST_ENGINE'],
      default: 'BUILTIN_DAST_ENGINE'
    },
    status: {
      type: String,
      enum: ['pending', 'running', 'completed', 'failed'],
      default: 'completed'
    },
    summary: {
      totalAlerts: { type: Number, default: 0 },
      highRiskCount: { type: Number, default: 0 },
      mediumRiskCount: { type: Number, default: 0 },
      lowRiskCount: { type: Number, default: 0 },
      infoCount: { type: Number, default: 0 },
      riskScore: { type: Number, default: 0 }, // 0 - 100
      grade: {
        type: String,
        enum: ['A+', 'A', 'B', 'C', 'D', 'F'],
        default: 'A'
      }
    },
    alerts: [dastAlertSchema],
    durationSeconds: { type: Number, default: 0 }
  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model('DastScan', dastScanSchema);

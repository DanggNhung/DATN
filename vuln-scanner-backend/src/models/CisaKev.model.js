const mongoose = require('mongoose');

const cisaKevSchema = new mongoose.Schema(
  {
    cveID: {
      type: String,
      required: true,
      unique: true,
      index: true,
      trim: true
    },
    vendorProject: {
      type: String,
      default: ''
    },
    product: {
      type: String,
      default: ''
    },
    vulnerabilityName: {
      type: String,
      default: ''
    },
    dateAdded: {
      type: String,
      default: ''
    },
    shortDescription: {
      type: String,
      default: ''
    },
    requiredAction: {
      type: String,
      default: ''
    },
    dueDate: {
      type: String,
      default: ''
    },
    knownRansomwareCampaignUse: {
      type: String,
      default: 'Unknown'
    },
    notes: {
      type: String,
      default: ''
    },
    lastSyncedAt: {
      type: Date,
      default: Date.now
    }
  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model('CisaKev', cisaKevSchema);

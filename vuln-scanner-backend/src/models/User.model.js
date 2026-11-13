const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, 'Vui lòng nhập tên người dùng'],
      unique: true,
      trim: true,
      minlength: [3, 'Tên người dùng tối thiểu 3 ký tự']
    },
    email: {
      type: String,
      required: [true, 'Vui lòng nhập email'],
      unique: true,
      trim: true,
      lowercase: true,
      match: [/^\S+@\S+\.\S+$/, 'Email không hợp lệ']
    },
    password: {
      type: String,
      required: [true, 'Vui lòng nhập mật khẩu'],
      minlength: [6, 'Mật khẩu tối thiểu 6 ký tự'],
      select: false // Không trả về password trong query thông thường
    },
    role: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user'
    },
    apiKey: {
      type: String,
      unique: true,
      index: true
    },
    isActive: {
      type: Boolean,
      default: true
    }
  },
  {
    timestamps: true
  }
);

// Tự động tạo API Key và băm mật khẩu trước khi lưu (Mongoose async hook)
userSchema.pre('save', async function () {
  if (!this.apiKey) {
    this.apiKey = 'vt_' + crypto.randomBytes(24).toString('hex');
  }

  if (!this.isModified('password')) {
    return;
  }

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

// So khớp mật khẩu
userSchema.methods.comparePassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Hàm làm mới API Key
userSchema.methods.regenerateApiKey = function () {
  this.apiKey = 'vt_' + crypto.randomBytes(24).toString('hex');
  return this.apiKey;
};

module.exports = mongoose.model('User', userSchema);

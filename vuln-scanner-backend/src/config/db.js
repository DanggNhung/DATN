const mongoose = require('mongoose');
const { MONGODB_URI } = require('./constants');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(MONGODB_URI, {
      autoIndex: true
    });
    console.log(`[+] MongoDB đã kết nối thành công: ${conn.connection.host}/${conn.connection.name}`);
  } catch (error) {
    console.error(`[-] Lỗi kết nối MongoDB: ${error.message}`);
    process.exit(1);
  }
};

module.exports = connectDB;

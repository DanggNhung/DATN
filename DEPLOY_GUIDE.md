# 🚀 Hướng Dẫn Triển Khai Hệ Thống SecShield Lên Vercel & Cloud

Tài liệu hướng dẫn chi tiết quy trình đưa ứng dụng **SecShield** (Frontend + Backend + Database) lên môi trường Internet để phục vụ nghiệm thu Đồ án Tốt nghiệp.

---

## 📌 Phân Tách Kiến Trúc Khi Đưa Lên Cloud

Hệ thống SecShield gồm 2 phần độc lập:
1. **Frontend (`vuln-scanner-frontend`)**: Viết bằng React + Vite. Nền tảng triển khai tối ưu nhất là **Vercel** (Global CDN tốc độ cao, hỗ trợ SSL miễn phí).
2. **Backend (`vuln-scanner-backend`)**: Node.js / Express, có tính năng Cron đồng bộ CVE CISA KEV, quét ZIP và kết nối MongoDB. Nền tảng phù hợp nhất là **Render.com** hoặc **Railway** (hỗ trợ tiến trình nền persistent 24/7), kết hợp với **MongoDB Atlas** (Database Cloud).

---

## 🅰️ PHẦN 1: Triển Khai Frontend Lên Vercel

Đã cấu hình sẵn:
- File [vercel.json](file:///d:/DATN/vuln-scanner-frontend/vercel.json) để xử lý định tuyến SPA (tránh lỗi 404 khi F5).
- Tích hợp biến môi trường `VITE_API_URL` trong [api.js](file:///d:/DATN/vuln-scanner-frontend/src/services/api.js) để linh hoạt trỏ tới Backend production hoặc chạy local.

Bạn có thể chọn 1 trong 2 cách sau:

### Cách 1: Deploy Bằng Giao Diện Vercel Web qua GitHub (Khuyên Dùng Nhất ⭐)

1. **Đẩy mã nguồn lên GitHub**:
   - Nếu chưa khởi tạo Git tại thư mục `d:\DATN`, mở Terminal và chạy:
     ```bash
     cd d:\DATN
     git init
     git add .
     git commit -m "feat: chuẩn bị cấu hình deploy Vercel"
     git branch -M main
     git remote add origin https://github.com/<tai-khoan-cua-ban>/<ten-repo>.git
     git push -u origin main
     ```

2. **Kết nối với Vercel**:
   - Truy cập [https://vercel.com](https://vercel.com) và đăng nhập bằng tài khoản **GitHub**.
   - Bấm nút **"Add New..."** ➔ **"Project"**.
   - Tìm repository vừa push và bấm **"Import"**.

3. **Cấu hình Project Settings trên Vercel**:
   - **Root Directory**: Bấm `Edit` và chọn thư mục `vuln-scanner-frontend`.
   - **Framework Preset**: Vercel sẽ tự nhận diện là `Vite`.
   - **Environment Variables**:
     - Key: `VITE_API_URL`
     - Value: Điền URL Backend của bạn (ví dụ: `https://secshield-api.onrender.com`). *Lưu ý: Nếu chưa deploy Backend, có thể bỏ trống bước này và thêm sau.*
   - Bấm nút **"Deploy"**.

Sau ~30 giây, Vercel sẽ cung cấp đường link live: `https://<ten-du-an>.vercel.app`.

---

### Cách 2: Deploy Nhanh Trực Tiếp Bằng Vercel CLI

Nếu bạn muốn deploy ngay từ máy tính mà không cần qua GitHub:

1. Mở PowerShell và di chuyển vào thư mục Frontend:
   ```bash
   cd d:\DATN\vuln-scanner-frontend
   ```

2. Chạy lệnh:
   ```bash
   npx vercel
   ```
   - Nhấn `Enter` để đăng nhập Vercel qua trình duyệt.
   - Trả lời các câu hỏi thiết lập:
     - `Set up and deploy “d:\DATN\vuln-scanner-frontend”?` ➔ Nhập `y`
     - `Which scope do you want to deploy to?` ➔ Chọn tài khoản của bạn
     - `Link to existing project?` ➔ Nhập `n`
     - `What’s your project’s name?` ➔ Đặt tên (ví dụ: `secshield-frontend`)
     - `In which directory is your code located?` ➔ Giữ nguyên `./`
   - Vercel sẽ tự build và trả về Preview URL.

3. Triển khai bản chính thức (Production):
   ```bash
   npx vercel --prod
   ```

---

## 🅱️ PHẦN 2: Triển Khai Backend & Database (Để Kết Nối Với Frontend)

Vì server cloud của Vercel không thể truy cập vào `mongodb://127.0.0.1:27017` trên máy cá nhân của bạn, Backend cần một Database Cloud:

1. **Tạo Database MongoDB Cloud (Miễn phí 100%)**:
   - Truy cập [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) và tạo một cụm **Shared (M0 - Free)**.
   - Vào mục **Network Access** ➔ Cho phép IP `0.0.0.0/0` (Allow Access from Anywhere).
   - Vào mục **Database Access** ➔ Tạo user/password cho ứng dụng.
   - Chọn **Connect** ➔ **Drivers** ➔ Sao chép chuỗi kết nối:
     `mongodb+srv://<username>:<password>@cluster0.xxx.mongodb.net/vuln_scanner_db?retryWrites=true&w=majority`

2. **Deploy Backend Lên Render.com (Miễn phí)**:
   - Truy cập [https://render.com](https://render.com) ➔ Chọn **New Web Service**.
   - Kết nối với Git repository của bạn.
   - Cấu hình:
     - **Root Directory**: `vuln-scanner-backend`
     - **Runtime**: `Node`
     - **Build Command**: `npm install`
     - **Start Command**: `node src/app.js`
   - Thêm các biến môi trường (**Environment Variables**):
     - `PORT`: `5000`
     - `MONGODB_URI`: Điền chuỗi kết nối MongoDB Atlas ở bước trên.
     - `JWT_SECRET`: Khóa bí mật JWT tùy ý.
     - `CISA_KEV_URL`: `https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json`
     - `OSV_API_URL`: `https://api.osv.dev/v1/query`
     - `OSV_BATCH_URL`: `https://api.osv.dev/v1/querybatch`
   - Bấm **Create Web Service**. Sau khi hoàn tất, Render sẽ cấp link Backend dạng: `https://secshield-backend.onrender.com`.

3. **Cập nhật URL Backend vào Vercel**:
   - Quay lại trang quản trị dự án trên Vercel ➔ **Settings** ➔ **Environment Variables**.
   - Thêm hoặc sửa biến:
     `VITE_API_URL` = `https://secshield-backend.onrender.com`
   - Vào tab **Deployments** ➔ Bấm **Redeploy** bản mới nhất để áp dụng.

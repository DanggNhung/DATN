# 🛡️ SecShield - Nền Tảng Đánh Giá An Toàn Chuỗi Cung Ứng Mã Nguồn (SCA) & Kiểm Thử Động API (DAST via OWASP ZAP)

> **Đồ Án Tốt Nghiệp Chuyên Ngành An Toàn Thông Tin / Công Nghệ Phần Mềm**  
> Nền tảng DevSecOps tích hợp: Phân tích Mã tĩnh (SCA), Kiểm thử Tấn công Động (DAST) và Threat Intelligence (CISA KEV).

---

## 📌 1. Giới thiệu Tổng quan

SecShield là hệ thống kiểm thử bảo mật toàn diện kết hợp các phương thức hàng đầu:
1. **Phân tích Chuỗi cung ứng (SCA - Software Composition Analysis):** Đọc file cấu hình (`package.json`, `requirements.txt`, `.zip`), trích xuất phiên bản và đối chiếu với **Google OSV** & **CISA KEV Catalog (1,746+ CVEs)** của Chính phủ Hoa Kỳ để phát hiện các thư viện bị chứa mã độc.
2. **Kiểm thử Động & Tấn công Thực nghiệm (DAST - Dynamic Application Security Testing):** Mô phỏng các kịch bản tấn công thực tế vào các Endpoint REST API đang chạy (tích hợp **OWASP ZAP API**) để phát hiện các lỗ hổng OWASP Top 10 API Security Risks (CORS Misconfiguration, Header thiếu sót, Rò rỉ Stack trace, HTTP Verb Tampering).
3. **Nhận Diện Thành Phần Website & Exploit-DB (Offensive Security Threat Feeds):** Tự động bóc tách các thành phần công nghệ trên trang web (Web Server, Runtime, CMS, UI Frameworks, JS Libraries) và tra cứu trực tiếp các bài khai thác công khai (Public PoC) trên **Exploit-DB** kèm mã **CVE** và cảnh báo rủi ro thực tế.
4. **VS Code Extension (Shift-Left Security):** Plugin cho phép lập trình viên quét mã nguồn và nhận cảnh báo rủi ro ngay tại IDE trong lúc viết mã.
5. **Báo cáo Thẩm định Chuyên nghiệp (Executive PDF Audit Report):** Xuất bản chứng thư đánh giá rủi ro chuẩn A4 kèm con dấu số kiểm định.

---

## 🏛️ 2. Kiến trúc Hệ thống (System Architecture)

```
                            [ Trình Duyệt Web ]            [ VS Code IDE ]
                         (React + Vite Cyber UI)      (secshield-scanner.vsix)
                                    │                           │
                                    │ HTTP / REST               │ API Key Auth
                                    ▼                           ▼
                        ┌──────────────────────────────────────────────┐
                        │       SecShield Backend API (Port 5000)      │
                        │    (Node.js / Express / Mongoose / JWT)      │
                        └───────┬──────────────┬──────────────┬────────┘
                                │              │              │
                 ┌──────────────┘              │              └──────────────┐
                 ▼                             ▼                             ▼
      ┌────────────────────┐        ┌────────────────────┐        ┌────────────────────┐
      │  MongoDB Database  │        │  Google OSV.dev &  │        │   OWASP ZAP DAST   │
      │  (Users, Scans,    │        │  CISA KEV Catalog  │        │   Engine (Daemon   │
      │   DAST, CISA KEV)  │        │  (Threat Feeds)    │        │   Port 8080 / API) │
      └────────────────────┘        └────────────────────┘        └────────────────────┘
```

---

## 🚀 3. Cấu trúc Thư mục

* `vuln-scanner-backend/`: Server REST API quản lý xác thực người dùng, quét tệp, giải nén `.zip`, so khớp CVE và đồng bộ CISA KEV.
* `vuln-scanner-frontend/`: Giao diện Web Portal hiện đại phong cách Dark Mode Cybersecurity (VirusTotal style) hiển thị điểm rủi ro và khuyến nghị vá lỗi.
* `secshield-vscode-extension/`: Tiện ích mở rộng VS Code đóng gói sẵn dạng `.vsix` để cài đặt trực tiếp.

---

## ⚙️ 4. Hướng dẫn Khởi chạy Hệ thống

### Bước 1: Khởi động MongoDB
Đảm bảo MongoDB Server đang chạy tại cổng `27017` (Mặc định service MongoDB của Windows).

### Bước 2: Khởi động Backend
```bash
cd vuln-scanner-backend
npm install
node src/app.js
```
* Backend sẽ lắng nghe tại: `http://localhost:5000`
* Tự động kết nối MongoDB và đồng bộ 1,746+ CVEs từ CISA KEV vào bộ nhớ cache.

### Bước 3: Khởi động Frontend
```bash
cd vuln-scanner-frontend
npm install
npm run dev
```
* Giao diện Web sẽ mở tại: `http://localhost:5173`

---

## 🔑 5. Tài khoản Quản trị viên (Admin) Mẫu

Hệ thống đã có sẵn tài khoản Admin dùng để demo bảo vệ đồ án:
* **Tên đăng nhập / Email:** `admin` hoặc `admin@devsecops.local`
* **Mật khẩu:** `AdminPassword123!`
* **Quyền:** Toàn quyền Quản trị (Xem Dashboard, Khóa/Mở User, Kích hoạt đồng bộ CISA KEV thủ công).

---

## 🔌 6. Hướng dẫn Cài đặt VS Code Extension (.vsix)

1. Truy cập Web Portal tại tab **VS Code Extension**, tải về tệp `secshield-scanner-1.0.0.vsix`.
2. Mở VS Code $\rightarrow$ bấm tổ hợp phím `Ctrl+Shift+P` $\rightarrow$ gõ `Extensions: Install from VSIX...` $\rightarrow$ chọn tệp vừa tải.
3. Cấu hình API Key: Bấm `Ctrl+Shift+P` $\rightarrow$ chọn `SecShield: Set API Key` và dán mã API Key được cấp trên Web.
4. Mở file `package.json` hoặc `requirements.txt` $\rightarrow$ Chuột phải chọn `SecShield: Quét Bảo Mật Dự Án`. Lỗi sẽ hiển thị ngay trong bảng **Problems** của VS Code!

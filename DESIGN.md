# 🌸 SecShield Design System (Pandora Luxury Blush Pink Theme)

Hệ thống thiết kế giao diện được chuẩn hóa theo phong cách **Luxury Minimalist & Pastel Blush Pink** lấy cảm hứng từ thương hiệu Pandora, kết hợp tính chất thẩm định bảo mật an ninh mạng (DevSecOps Cybersecurity).

---

## 🎨 1. Bảng Màu (Color Tokens)

### Nền (Surfaces & Backgrounds)
- **Primary Background:** `#fff8f9` (Soft Rose Cream với radial gradients dịu nhẹ)
- **Card Background:** `#ffffff` (Pure Crisp White)
- **Tertiary Surface:** `#fdf2f8` (Pastel Blush Pink)
- **Border Subtle:** `#fce7f3` (Đường viền hồng pastel mảnh 1px)
- **Border Focus / Accent:** `#ec4899` (Vibrant Rose Pink)

### Điểm nhấn & Hành động (Brand Accents)
- **Primary CTA Gradient:** `linear-gradient(135deg, #f472b6, #db2777)` (Rose Pink to Magenta)
- **Top Announcement Bar:** `linear-gradient(90deg, #fbcfe8, #fce7f3, #fbcfe8)` với chữ `#831843`
- **Secondary Buttons:** Nền `#ffffff`, viền `#fce7f3`, hover hiệu ứng hồng nhạt `#fdf2f8`

### Huy hiệu Phân loại Rủi ro (Severity Badges)
- **Critical / Exploit-DB PoC:** Nền `#fff1f2`, viền `#fecdd3`, chữ `#be123c`
- **High Risk:** Nền `#fff7ed`, viền `#fed7aa`, chữ `#c2410c`
- **Medium Risk:** Nền `#fdf2f8`, viền `#fce7f3`, chữ `#be185d`
- **Safe / Secure:** Nền `#ecfdf5`, viền `#a7f3d0`, chữ `#047857`
- **CISA KEV (Active Exploit):** Gradient `#ffe4e6` $\rightarrow$ `#fce7f3`, viền `#fda4af`, chữ `#9f1239`

---

## 🔤 2. Kiểu Chữ (Typography Hierarchy)

- **Display / Headings / Logo:** `Montserrat` (Sans-serif hình học sang trọng, tracking `0.08em` đến `0.15em`, `text-transform: uppercase`).
- **Body / Content:** `Plus Jakarta Sans` (Sans-serif hiện đại, độ tương phản cao, nét chữ thanh lịch và dễ đọc).
- **Code / Manifest / EDB-ID:** `JetBrains Mono` (Monospace chuẩn kỹ thuật).

---

## 💎 3. Thành Phần Giao Diện Đặc Trưng (Components)

1. **Top Announcement Bar (Pandora Style):** Thanh thông báo màu hồng pastel trên cùng, căn giữa, chữ in hoa thanh mảnh.
2. **Glass Cards:** Đổ bóng hồng khói phân tán mềm mại (`box-shadow: 0 8px 25px -4px rgba(236, 72, 153, 0.08)`).
3. **Logo SECSHIELD:** Phong cách thương hiệu trang sức cao cấp với khoảng cách ký tự rộng và badge hồng ngọc.

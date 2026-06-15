# Dokumentasi Projek: MERN Authentication V.me

## 📌 Deskripsi Projek

Projek **MERN Authentication V.me** adalah sistem autentikasi full-stack tingkat lanjut yang dibangun menggunakan arsitektur MERN (MongoDB, Express.js, React.js, Node.js). Projek ini dirancang untuk memberikan solusi manajemen identitas yang aman, cepat, dan siap untuk tahap produksi, berfokus pada fleksibilitas login, perlindungan keamanan tingkat tinggi, serta antarmuka pengguna (UI) modern.

---

## 🛠️ Arsitektur & Teknologi

### Frontend

- **Framework & Build Tool**: React.js dengan Vite
- **Styling**: Tailwind CSS & Shadcn UI
- **State Management**: Zustand
- **Routing**: React Router DOM
- **HTTP Client**: Axios
- **Iconography & Components**: Lucide React, Class Variance Authority (CVA), Input OTP

### Backend

- **Core Environment**: Node.js & Express.js
- **Database & ODM**: MongoDB dengan Mongoose
- **Caching**: Redis (menggunakan `ioredis`)
- **Dokumentasi API**: Swagger UI Express & Swagger JSDoc

---

## 🚀 Fitur Lengkap Sistem

### 1. Sistem Autentikasi (Authentication System)

- **Local Authentication**: Registrasi, Login, dan manajemen pengguna menggunakan kombinasi Email & Password konvensional. (Password di-hash secara aman dengan `bcrypt`).
- **OAuth & Social Login**: Integrasi menyeluruh dengan penyedia layanan pihak ketiga melalui konfigurasi **Passport.js**:
  - Login dengan Google (`passport-google-oauth20`)
  - Login dengan GitHub (`passport-github2`)
  - Login dengan Discord (`passport-discord`)
  - Login dengan Twitter (`passport-twitter`)
- **JSON Web Token (JWT)**: Implementasi penerbitan, verifikasi, dan refresh token yang aman untuk menjaga sesi pengguna agar tetap stateless namun terlindungi.
- **BLACKLIST JSON Web Token (JWT) Using Redis**: Implementasi Blacklist refresh token menggunakan Redis.

### 2. Multi-Factor Authentication (MFA / 2FA)

- Dukungan keamanan ganda menggunakan kode sandi sekali pakai berbasis waktu (TOTP) melalui pustaka `speakeasy`.
- Men-generate tautan dan gambar **QR Code** otomatis (`qrcode`) untuk dipindai oleh aplikasi authenticator seperti Google Authenticator, Authy, atau Microsoft Authenticator.
- Terdapat komponen UI khusus berbasis `input-otp` di frontend untuk mempermudah pengalaman memasukkan pin MFA.

### 3. Keamanan Tingkat Lanjut (Security Measures)

Sistem backend dirancang dengan lapis pelindung berlapis guna meminimalisir celah eksploitasi peretas:

- **Rate Limiting**: Pembatasan jumlah permintaan akses API secara temporal menggunakan `express-rate-limit` untuk memblokir serangan _Brute Force_ dan DDoS ringan.
- **Sanitasi Data**: Menetralisir bahaya serangan _NoSQL Injection_ menggunakan pustaka `express-mongo-sanitize`.
- **Pencegahan XSS**: Mengatasi ancaman script lintas situs (Cross-Site Scripting) menggunakan paket modul `xss`.
- **Helmet**: Meningkatkan sekuritas dari HTTP Header secara instan dengan middleware `helmet`.
- **CORS Configuration**: Pengaturan Cross-Origin Resource Sharing (CORS) yang ketat untuk mengizinkan dan memblokir lalu lintas dari asal tertentu.
- **Turnstile Cloudflare**: Implementasi CAPTCHA alternatif dari Cloudflare untuk melindungi endpoint kritis (registrasi, login, lupa password) dari serangan bot tanpa mengganggu pengalaman pengguna. Bekerja secara otomatis dengan analisis risiko berbasis perilaku.

### 4. Manajemen Email & Pemulihan Akun

- Terintegrasi dengan SMTP layanan pengiriman surel menggunakan **Nodemailer**.
- **Verifikasi Email**: Pengiriman token satu-kali pakai agar pengguna dapat memverifikasi email pendaftaran mereka.
- **Lupa Kata Sandi (Forgot Password)**: Mengirimkan tautan penyetelan ulang kata sandi ke dalam alamat email (reset token dengan masa kedaluwarsa).

### 5. Sistem Monitoring & Logging

- **Winston & Morgan Logs**: Seluruh request ke dalam server beserta potensi error akan dicatat (logging) oleh `winston` dan `morgan`.
- **Daily Log Rotation**: Sistem otomatis me-rotate log dan mencadangkan file error tiap harinya (`winston-daily-rotate-file`) agar memory storage server tidak tersumbat.

### 6. Antarmuka Pengguna Modern (Frontend UI/UX)

- Dibangun dengan utilitas dan kerangka UI yang sangat bersih (Tailwind CSS + Shadcn UI).
- Transisi dan animasi halus untuk UX yang premium (melalui integrasi `tw-animate-css` dan `tailwindcss-animate`).
- Layout responsif yang dapat digunakan secara optimal di perangkat Mobile maupun Desktop.

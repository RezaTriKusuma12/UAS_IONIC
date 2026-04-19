const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
let otpStore = {};
let otpCooldown = {};

console.log('SERVER MULAI...');

const app = express();
app.use(express.json());
app.use(cors());

const nodemailer = require('nodemailer');
require('dotenv').config();

// 🔐 GANTI DENGAN EMAIL KAMU
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS // ⚠️ bukan password biasa
  }
});

// koneksi database
//const db = mysql.createConnection({
 // host: 'localhost',
 // user: 'root',
 // password: '',
 //database: 'logista_app'
//});

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
});

// cek koneksi database
db.connect((err) => {
  if (err) {
    console.log('❌ Koneksi database gagal:', err);
  } else {
    console.log('✅ Koneksi database berhasil');
  }
});

// test API
app.get('/', (req, res) => {
  res.json({ message: 'API Logista jalan' });
});


// ================= REGISTER =================
app.post('/register', async (req, res) => {
  const { name, email, username, password } = req.body;

  if (!name || !email || !username || !password) {
    return res.status(400).json({ message: 'Data tidak lengkap' });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);

    db.query(
      'INSERT INTO users (name, email, username, password) VALUES (?, ?, ?, ?)',
      [name, email, username, hashed],
      (err) => {
        if (err) {
          console.log('❌ Error register:', err);

          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ message: 'Email sudah terdaftar' });
          }

          return res.status(500).json({ message: 'Register gagal' });
        }

        res.status(200).json({ message: 'Register berhasil' });
      }
    );

  } catch (error) {
    console.log('❌ Hash error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});


// ================= LOGIN =================
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  db.query(
    'SELECT * FROM users WHERE email = ?',
    [email],
    async (err, results) => {

      if (err) {
        console.log('❌ Error login:', err);
        return res.status(500).json({ message: 'Error database' });
      }

      if (results.length === 0) {
        return res.status(404).json({ message: 'User tidak ada' });
      }

      const user = results[0];
      const match = await bcrypt.compare(password, user.password);

      if (!match) {
        return res.status(401).json({ message: 'Password salah' });
      }

      res.status(200).json({
        message: 'Login berhasil',
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          username: user.username
        }
      });
    }
  );
});

// ================= LUPA PASSWORD (KIRIM OTP) =================
//let otpStore = {}; // simpan OTP sementara

app.post('/lupa-password', (req, res) => {
  const { email } = req.body;

  // 🔥 CEK COOLDOWN (ANTI SPAM)
  if (otpCooldown[email] && Date.now() < otpCooldown[email]) {
    return res.status(429).json({
      message: 'Tunggu 60 detik sebelum kirim ulang OTP'
    });
  }

  db.query(
    'SELECT * FROM users WHERE email = ?',
    [email],
    (err, results) => {

      if (err) return res.status(500).json({ message: 'DB error' });

      if (results.length === 0) {
        return res.status(404).json({ message: 'Email tidak ditemukan' });
      }

      const otp = Math.floor(1000 + Math.random() * 9000);

      // 🔐 SIMPAN OTP + EXPIRE
      otpStore[email] = {
        code: otp,
        expire: Date.now() + 5 * 60 * 1000 // 5 menit
      };

      // ⏳ SET COOLDOWN 60 DETIK
      otpCooldown[email] = Date.now() + 60 * 1000;

      // 📧 KIRIM EMAIL OTP
const mailOptions = {
  from: 'Logista App <emailkamu@gmail.com>',
  to: email,
  subject: 'Kode OTP Reset Password',
  html: `
    <h3>Reset Password</h3>
    <p>Kode OTP kamu adalah:</p>
    <h1>${otp}</h1>
    <p>Berlaku 5 menit</p>
  `
};

transporter.sendMail(mailOptions, (error, info) => {
  if (error) {
    console.log('❌ Gagal kirim email:', error);
    return res.status(500).json({ message: 'Gagal kirim email' });
  }

  console.log('✅ Email terkirim:', info.response);

  res.json({ message: 'OTP dikirim ke email' });
});
    }
  );
});

// ================= VERIFY OTP =================
app.post('/masukkan-otp', (req, res) => {
  const { email, otp } = req.body;

  const data = otpStore[email];

  if (!data) {
    return res.status(400).json({ message: 'OTP tidak ada' });
  }

  // 🔥 cek expired
  if (Date.now() > data.expire) {
    delete otpStore[email];
    return res.status(400).json({ message: 'OTP sudah expired' });
  }

  // 🔥 cek kode OTP
  if (data.code == otp) {

    // ✅ tandai OTP sudah diverifikasi
    otpStore[email].verified = true;

    return res.json({ message: 'OTP valid' });
  } else {
    return res.status(400).json({ message: 'OTP salah' });
  }
});

// ================= RESET PASSWORD =================
app.post('/reset-password', async (req, res) => {
  const { email, password } = req.body;

  const data = otpStore[email];

  // 🔥 pastikan OTP sudah diverifikasi
  if (!data) {
    return res.status(400).json({ message: 'OTP belum diverifikasi' });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);

    db.query(
      'UPDATE users SET password = ? WHERE email = ?',
      [hashed, email],
      (err, result) => {

        if (err) return res.status(500).json({ message: 'Gagal update' });

        delete otpStore[email]; // hapus OTP setelah dipakai

        res.json({ message: 'Password berhasil diubah' });
      }
    );

  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});
// ================= START SERVER =================
app.listen(3000, () => {
  console.log('🚀 Server jalan di http://localhost:3000');
});


// HANDLE ERROR BIAR GA DIAM
process.on('uncaughtException', (err) => {
  console.error('❌ ERROR BESAR:', err);
});
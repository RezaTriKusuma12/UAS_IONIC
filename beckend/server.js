const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8000;

app.use(cors());
app.use(express.json());

const otpStore = {};
const otpCooldown = {};

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// =====================================
// HELPER
// =====================================

function sendError(res, err, message = 'Terjadi kesalahan server', status = 500) {
  console.error(message, err);

  return res.status(status).json({
    success: false,
    message,
    error: process.env.NODE_ENV === 'development' ? err.message : undefined,
  });
}

function handleAsync(callback) {
  return async (req, res) => {
    try {
      await callback(req, res);
    } catch (err) {
      return sendError(res, err, err.message || 'Terjadi kesalahan server', err.status || 500);
    }
  };
}

async function runTransaction(callback) {
  const connection = await db.getConnection();

  try {
    await connection.beginTransaction();
    const result = await callback(connection);
    await connection.commit();
    return result;
  } catch (err) {
    await connection.rollback();
    throw err;
  } finally {
    connection.release();
  }
}

async function saveStockSnapshot() {
  const [rows] = await db.query(`
    SELECT COALESCE(SUM(stok_gudang + stok_rak), 0) AS total_stok
    FROM barangs
  `);

  await db.query(
    `INSERT INTO stock_snapshots (total_stok, created_at) VALUES (?, NOW())`,
    [rows[0].total_stok]
  );
}

async function createNotification(connection, { title, message, type, pemesananId = null }) {
  await connection.query(
    `
      INSERT INTO notifications
      (title, message, type, pemesanan_id, is_read, created_at)
      VALUES (?, ?, ?, ?, 0, NOW())
    `,
    [title, message, type, pemesananId]
  );
}

async function closePemesananNotification(connection, pemesananId) {
  await connection.query(
    `
      UPDATE notifications
      SET is_read = 1
      WHERE type = 'pemesanan'
      AND pemesanan_id = ?
    `,
    [pemesananId]
  );
}

// =====================================
// TEST API
// =====================================

app.get('/api', (req, res) => {
  res.json({
    success: true,
    message: 'API Logista jalan',
  });
});

// =====================================
// AUTH
// =====================================

app.post('/api/register', handleAsync(async (req, res) => {
  const { name, email, username, password } = req.body;

  if (!name || !email || !username || !password) {
    return res.status(400).json({
      success: false,
      message: 'Data tidak lengkap',
    });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    await db.query(
      `
        INSERT INTO users
        (name, email, username, password)
        VALUES (?, ?, ?, ?)
      `,
      [name, email, username, hashedPassword]
    );

    return res.status(201).json({
      success: true,
      message: 'Register berhasil',
    });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({
        success: false,
        message: 'Email atau username sudah terdaftar',
      });
    }

    throw err;
  }
}));

app.post('/api/login', handleAsync(async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: 'Email dan password wajib diisi',
    });
  }

  const [rows] = await db.query(
    `SELECT * FROM users WHERE email = ?`,
    [email]
  );

  if (rows.length === 0) {
    return res.status(404).json({
      success: false,
      message: 'User tidak ada',
    });
  }

  const user = rows[0];
  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    return res.status(401).json({
      success: false,
      message: 'Password salah',
    });
  }

  return res.json({
    success: true,
    message: 'Login berhasil',
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      username: user.username,
    },
  });
}));

app.post('/api/lupa-password', handleAsync(async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({
      success: false,
      message: 'Email wajib diisi',
    });
  }

  if (otpCooldown[email] && Date.now() < otpCooldown[email]) {
    return res.status(429).json({
      success: false,
      message: 'Tunggu 60 detik sebelum kirim ulang OTP',
    });
  }

  const [rows] = await db.query(
    `SELECT id, email FROM users WHERE email = ?`,
    [email]
  );

  if (rows.length === 0) {
    return res.status(404).json({
      success: false,
      message: 'Email tidak ditemukan',
    });
  }

  const otp = Math.floor(1000 + Math.random() * 9000);

  otpStore[email] = {
    code: otp,
    verified: false,
    expire: Date.now() + 5 * 60 * 1000,
  };

  otpCooldown[email] = Date.now() + 60 * 1000;

  await transporter.sendMail({
    from: 'Logista App <emailkamu@gmail.com>',
    to: email,
    subject: 'Kode OTP Reset Password',
    html: `
      <h3>Reset Password</h3>
      <p>Kode OTP kamu adalah:</p>
      <h1>${otp}</h1>
      <p>Berlaku 5 menit.</p>
    `,
  });

  return res.json({
    success: true,
    message: 'OTP dikirim ke email',
  });
}));

app.post('/api/masukkan-otp', (req, res) => {
  const { email, otp } = req.body;
  const data = otpStore[email];

  if (!data) {
    return res.status(400).json({
      success: false,
      message: 'OTP tidak ada',
    });
  }

  if (Date.now() > data.expire) {
    delete otpStore[email];

    return res.status(400).json({
      success: false,
      message: 'OTP sudah expired',
    });
  }

  if (String(data.code) !== String(otp)) {
    return res.status(400).json({
      success: false,
      message: 'OTP salah',
    });
  }

  otpStore[email].verified = true;

  return res.json({
    success: true,
    message: 'OTP valid',
  });
});

app.post('/api/reset-password', handleAsync(async (req, res) => {
  const { email, password } = req.body;
  const data = otpStore[email];

  if (!data || !data.verified) {
    return res.status(400).json({
      success: false,
      message: 'OTP belum diverifikasi',
    });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  await db.query(
    `UPDATE users SET password = ? WHERE email = ?`,
    [hashedPassword, email]
  );

  delete otpStore[email];

  return res.json({
    success: true,
    message: 'Password berhasil diubah',
  });
}));

// =====================================
// BARANG
// =====================================

app.get('/api/barang', handleAsync(async (req, res) => {
  const [rows] = await db.query(`
    SELECT *, (stok_gudang + stok_rak) AS total_stok
    FROM barangs
    ORDER BY id DESC
  `);

  return res.json({
    success: true,
    data: rows,
  });
}));

app.get('/api/barang/:id', handleAsync(async (req, res) => {
  const [rows] = await db.query(
    `
      SELECT *, (stok_gudang + stok_rak) AS total_stok
      FROM barangs
      WHERE id = ?
    `,
    [req.params.id]
  );

  if (rows.length === 0) {
    return res.status(404).json({
      success: false,
      message: 'Barang tidak ditemukan',
    });
  }

  return res.json({
    success: true,
    data: rows[0],
  });
}));

// =====================================
// PEMESANAN BARANG
// =====================================

app.post('/api/pemesanan', handleAsync(async (req, res) => {
  const { barang_id, jumlah_pesan, nama_supplier } = req.body;

  if (!barang_id || !jumlah_pesan || !nama_supplier) {
    return res.status(400).json({
      success: false,
      message: 'Data belum lengkap',
    });
  }

  const result = await runTransaction(async (connection) => {
    const [barangRows] = await connection.query(
      `
        SELECT id, nama_barang, kode_barang, satuan
        FROM barangs
        WHERE id = ?
      `,
      [barang_id]
    );

    if (barangRows.length === 0) {
      const error = new Error('Barang tidak ditemukan');
      error.status = 404;
      throw error;
    }

    const barang = barangRows[0];

    const [insertResult] = await connection.query(
      `
        INSERT INTO pemesanan_barang
        (barang_id, jumlah_pesan, nama_supplier, status, created_at)
        VALUES (?, ?, ?, 'pending', NOW())
      `,
      [barang_id, jumlah_pesan, nama_supplier]
    );

    await createNotification(connection, {
      title: '📦 Pemesanan Baru',
      message: `${barang.nama_barang} dipesan sebanyak ${jumlah_pesan} ${barang.satuan || 'pcs'} dari supplier ${nama_supplier}`,
      type: 'pemesanan',
      pemesananId: insertResult.insertId,
    });

    return {
      pemesanan_id: insertResult.insertId,
      barang: barang.nama_barang,
      qty: jumlah_pesan,
      supplier: nama_supplier,
    };
  });

  return res.status(201).json({
    success: true,
    message: 'Pemesanan berhasil ditambahkan',
    data: result,
  });
}));

app.get('/api/pemesanan', handleAsync(async (req, res) => {
  const [rows] = await db.query(`
    SELECT
      pemesanan_barang.*,
      barangs.nama_barang,
      barangs.kode_barang,
      barangs.satuan
    FROM pemesanan_barang
    LEFT JOIN barangs ON pemesanan_barang.barang_id = barangs.id
    ORDER BY pemesanan_barang.id DESC
  `);

  return res.json({
    success: true,
    data: rows,
  });
}));

// =====================================
// VERIFIKASI BARANG MASUK
// =====================================

app.post('/api/verifikasi-barang', handleAsync(async (req, res) => {
  const {
    user_id,
    pemesanan_id,
    barang_id,
    qty_diterima,
    status,
    catatan,
  } = req.body;

  const qty = Number(qty_diterima || 0);

  if (!user_id || !pemesanan_id || !barang_id || !status) {
    return res.status(400).json({
      success: false,
      message: 'Data belum lengkap',
    });
  }

  if (!['diterima', 'ditolak'].includes(status)) {
    return res.status(400).json({
      success: false,
      message: 'Status tidak valid',
    });
  }

  if (status === 'diterima' && qty <= 0) {
    return res.status(400).json({
      success: false,
      message: 'Qty diterima harus lebih dari 0',
    });
  }

  await runTransaction(async (connection) => {
    const [barangRows] = await connection.query(
      `
        SELECT id, stok_gudang, stok_rak
        FROM barangs
        WHERE id = ?
      `,
      [barang_id]
    );

    if (barangRows.length === 0) {
      const error = new Error('Barang tidak ditemukan');
      error.status = 404;
      throw error;
    }

    const barang = barangRows[0];

    const totalSebelum =
      Number(barang.stok_gudang) +
      Number(barang.stok_rak);

    const gudangSebelum =
      Number(barang.stok_gudang);

    const rakSebelum =
      Number(barang.stok_rak);

    const totalSesudah =
      status === 'diterima'
        ? totalSebelum + qty
        : totalSebelum;

    const gudangSesudah =
      status === 'diterima'
        ? gudangSebelum + qty
        : gudangSebelum;

    const rakSesudah =
      rakSebelum;

    if (status === 'diterima') {
      await connection.query(
        `
          UPDATE barangs
          SET stok_gudang = stok_gudang + ?
          WHERE id = ?
        `,
        [qty, barang_id]
      );
    }

    await connection.query(
      `
        UPDATE pemesanan_barang
        SET status = ?, qty_diterima = ?, catatan = ?, verified_at = NOW()
        WHERE id = ?
      `,
      [status, qty, catatan || null, pemesanan_id]
    );

    await connection.query(
      `
        INSERT INTO transaksis
        (
          user_id,
          jenis,
          barang_id,
          jumlah,
          total_stok_sebelum,
          total_stok_sesudah,
          stok_gudang_sebelum,
          stok_gudang_sesudah,
          stok_rak_sebelum,
          stok_rak_sesudah,
          keterangan,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
      `,
      [
        user_id,
        status === 'diterima' ? 'barang_masuk' : 'barang_ditolak',
        barang_id,
        qty,
        totalSebelum,
        totalSesudah,
        gudangSebelum,
        gudangSesudah,
        rakSebelum,
        rakSesudah,
        catatan || (status === 'diterima' ? 'Barang masuk diverifikasi' : 'Barang ditolak'),
      ]
    );

    await closePemesananNotification(connection, pemesanan_id);
  });

  saveStockSnapshot()
    .catch((err) => console.error('Gagal simpan snapshot:', err));

  return res.json({
    success: true,
    message: 'Verifikasi barang berhasil',
  });
}));

// =====================================
// BARANG KELUAR
// =====================================

app.post('/api/barang-keluar', handleAsync(async (req, res) => {
  const {
    user_id,
    barang_id,
    qty_keluar,
    tujuan,
    catatan,
  } = req.body;

  const qty = Number(qty_keluar || 0);

  if (!user_id || !barang_id || !qty || !tujuan) {
    return res.status(400).json({
      success: false,
      message: 'Data belum lengkap',
    });
  }

  await runTransaction(async (connection) => {
    const [barangRows] = await connection.query(
      `SELECT * FROM barangs WHERE id = ?`,
      [barang_id]
    );

    if (barangRows.length === 0) {
      const error = new Error('Barang tidak ditemukan');
      error.status = 404;
      throw error;
    }

    const barang = barangRows[0];

    const totalSebelum =
      Number(barang.stok_gudang) +
      Number(barang.stok_rak);

    const gudangSebelum =
      Number(barang.stok_gudang);

    const rakSebelum =
      Number(barang.stok_rak);

    if (qty > rakSebelum) {
      const error = new Error('Stok rak tidak mencukupi');
      error.status = 400;
      throw error;
    }

    const rakSesudah =
      rakSebelum - qty;

    const totalSesudah =
      totalSebelum - qty;

    await connection.query(
      `
        UPDATE barangs
        SET stok_rak = ?
        WHERE id = ?
      `,
      [rakSesudah, barang_id]
    );

    await connection.query(
      `
        INSERT INTO barang_keluar
        (barang_id, qty_keluar, tujuan, catatan)
        VALUES (?, ?, ?, ?)
      `,
      [barang_id, qty, tujuan, catatan || null]
    );

    await connection.query(
      `
        INSERT INTO transaksis
        (
          user_id,
          jenis,
          barang_id,
          jumlah,
          total_stok_sebelum,
          total_stok_sesudah,
          stok_gudang_sebelum,
          stok_gudang_sesudah,
          stok_rak_sebelum,
          stok_rak_sesudah,
          keterangan,
          created_at,
          updated_at
        )
        VALUES (?, 'barang_keluar', ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
      `,
      [
        user_id,
        barang_id,
        qty,
        totalSebelum,
        totalSesudah,
        gudangSebelum,
        gudangSebelum,
        rakSebelum,
        rakSesudah,
        catatan || tujuan,
      ]
    );
  });

  saveStockSnapshot()
    .catch((err) => console.error('Gagal simpan snapshot:', err));

  return res.json({
    success: true,
    message: 'Barang berhasil dikeluarkan',
  });
}));

// =====================================
// MUTASI BARANG
// =====================================

app.post('/api/mutasi-barang', handleAsync(async (req, res) => {
  const {
    user_id,
    barang_id,
    qty_mutasi,
    lokasi_asal,
    lokasi_tujuan,
    catatan,
  } = req.body;

  const qty = Number(qty_mutasi || 0);

  if (!user_id || !barang_id || !qty || !lokasi_asal || !lokasi_tujuan) {
    return res.status(400).json({
      success: false,
      message: 'Data belum lengkap',
    });
  }

  await runTransaction(async (connection) => {
    const [barangRows] = await connection.query(
      `SELECT * FROM barangs WHERE id = ?`,
      [barang_id]
    );

    if (barangRows.length === 0) {
      const error = new Error('Barang tidak ditemukan');
      error.status = 404;
      throw error;
    }

    const barang = barangRows[0];

    const totalSebelum =
      Number(barang.stok_gudang) +
      Number(barang.stok_rak);

    const gudangSebelum =
      Number(barang.stok_gudang);

    const rakSebelum =
      Number(barang.stok_rak || 0);

    if (qty > gudangSebelum) {
      const error = new Error('Stok gudang tidak mencukupi');
      error.status = 400;
      throw error;
    }

    const gudangSesudah =
      gudangSebelum - qty;

    const rakSesudah =
      rakSebelum + qty;

    await connection.query(
      `
        UPDATE barangs
        SET stok_gudang = ?, stok_rak = ?, lokasi_rak = ?
        WHERE id = ?
      `,
      [gudangSesudah, rakSesudah, lokasi_tujuan, barang_id]
    );

    await connection.query(
      `
        INSERT INTO mutasi_barang
        (barang_id, qty_mutasi, lokasi_asal, lokasi_tujuan, catatan)
        VALUES (?, ?, ?, ?, ?)
      `,
      [barang_id, qty, lokasi_asal, lokasi_tujuan, catatan || null]
    );

    await connection.query(
      `
        INSERT INTO transaksis
        (
          user_id,
          jenis,
          barang_id,
          jumlah,
          total_stok_sebelum,
          total_stok_sesudah,
          stok_gudang_sebelum,
          stok_gudang_sesudah,
          stok_rak_sebelum,
          stok_rak_sesudah,
          keterangan,
          created_at,
          updated_at
        )
        VALUES (?, 'mutasi', ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
      `,
      [
        user_id,
        barang_id,
        qty,
        totalSebelum,
        totalSebelum,
        gudangSebelum,
        gudangSesudah,
        rakSebelum,
        rakSesudah,
        catatan || `Mutasi dari ${lokasi_asal} ke ${lokasi_tujuan}`,
      ]
    );
  });

  saveStockSnapshot()
    .catch((err) => console.error('Gagal simpan snapshot:', err));

  return res.json({
    success: true,
    message: 'Mutasi barang berhasil',
  });
}));

// =====================================
// DASHBOARD ANALYTICS
// =====================================

app.get('/api/dashboard-stock', handleAsync(async (req, res) => {
  const [rows] = await db.query(`
    SELECT
      (SELECT COUNT(*) FROM barangs) AS total_barang,
      (SELECT COALESCE(SUM(stok_gudang + stok_rak), 0) FROM barangs) AS total_stok,
      (SELECT COUNT(*) FROM barangs WHERE (stok_gudang + stok_rak) < stok_minimum) AS low_stock,
      (SELECT COUNT(*) FROM transaksis WHERE jenis = 'barang_masuk') AS barang_masuk,
      (SELECT COUNT(*) FROM transaksis WHERE jenis = 'barang_keluar') AS barang_keluar,
      (SELECT COUNT(*) FROM transaksis WHERE jenis = 'mutasi') AS mutasi,
      (SELECT COUNT(*) FROM transaksis WHERE jenis = 'barang_ditolak') AS barang_ditolak
  `);

  return res.json({
    success: true,
    data: rows[0],
  });
}));

// =====================================
// HISTORY TRANSAKSI
// =====================================

app.get('/api/inventory-history', handleAsync(async (req, res) => {
  const [rows] = await db.query(`
    SELECT
      transaksis.*,
      barangs.nama_barang,
      barangs.kode_barang
    FROM transaksis
    JOIN barangs ON transaksis.barang_id = barangs.id
    ORDER BY transaksis.created_at DESC
  `);

  return res.json({
    success: true,
    data: rows,
  });
}));

// =====================================
// GRAFIK PERUBAHAN STOK
// =====================================

app.get('/api/stock-line-chart', handleAsync(async (req, res) => {
  const bulan = Number(req.query.bulan);
  const minggu = Number(req.query.minggu);
  const tahun = Number(req.query.tahun);

  if (!bulan || !minggu || !tahun) {
    return res.status(400).json({
      success: false,
      message: 'Parameter tidak lengkap',
    });
  }

  const weekRanges = {
    1: [1, 7],
    2: [8, 14],
    3: [15, 21],
    4: [22, 31],
  };

  const [startDay, endDay] =
    weekRanges[minggu] || weekRanges[1];

  const [rows] = await db.query(
    `
      SELECT DATE(created_at) AS tanggal, total_stok, created_at
      FROM stock_snapshots
      WHERE YEAR(created_at) = ?
      AND MONTH(created_at) = ?
      AND DAY(created_at) BETWEEN ? AND ?
      ORDER BY created_at ASC
    `,
    [tahun, bulan, startDay, endDay]
  );

  const latestPerDate = {};

  rows.forEach((item) => {
    latestPerDate[item.tanggal] = item;
  });

  return res.json({
    success: true,
    data: Object.values(latestPerDate),
  });
}));

// =====================================
// NOTIFICATIONS INTERNAL IONIC
// =====================================

app.get('/api/notifications', handleAsync(async (req, res) => {
  const [rows] = await db.query(`
    SELECT
      id,
      title,
      message,
      type,
      pemesanan_id,
      is_read,
      created_at
    FROM notifications
    WHERE is_read = 0
    ORDER BY id DESC
    LIMIT 10
  `);

  return res.json({
    success: true,
    data: rows,
  });
}));

app.get('/api/notifications-count', handleAsync(async (req, res) => {
  const [rows] = await db.query(`
    SELECT COUNT(*) AS total
    FROM notifications
    WHERE is_read = 0
  `);

  return res.json({
    success: true,
    total: rows[0].total,
  });
}));

// =====================================
// NOT FOUND & ERROR HANDLER
// =====================================

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route tidak ditemukan',
  });
});

process.on('uncaughtException', (err) => {
  console.error('ERROR BESAR:', err);
});

process.on('unhandledRejection', (err) => {
  console.error('UNHANDLED PROMISE:', err);
});

// =====================================
// START SERVER
// =====================================

app.listen(PORT, async () => {
  try {
    await db.query('SELECT 1');
    console.log('Koneksi database berhasil');
  } catch (err) {
    console.error('Koneksi database gagal:', err);
  }

  console.log(`Server jalan di http://localhost:${PORT}`);
});
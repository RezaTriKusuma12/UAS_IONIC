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

// =====================================
// SAVE STOCK SNAPSHOT
// =====================================

function saveStockSnapshot() {

  const sqlTotal = `

    SELECT
      SUM(stok_gudang + stok_rak)
      AS total_stok

    FROM barangs

  `;

  db.query(sqlTotal, (err, result) => {

    if (err) {

      console.log(
        'Snapshot error:',
        err
      );

      return;

    }

    const totalStok =

      result[0].total_stok || 0;

    // =========================
    // SIMPAN SNAPSHOT
    // =========================

    const sqlInsert = `

      INSERT INTO stock_snapshots
      (
        total_stok
      )

      VALUES (?)

    `;

    db.query(

      sqlInsert,

      [totalStok],

      (err2) => {

        if (err2) {

          console.log(

            'Gagal simpan snapshot:',
            err2

          );

        }

      }

    );

  });

}
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



// HANDLE ERROR BIAR GA DIAM
process.on('uncaughtException', (err) => {
  console.error('❌ ERROR BESAR:', err);
});

// =====================================
// DAFTAR BARANG
// =====================================

app.get('/api/barang', (req, res) => {

  const sql = `

    SELECT
      *,
      (stok_gudang + stok_rak)
      AS total_stok

    FROM barangs

    ORDER BY id DESC

  `;

  db.query(sql, (err, result) => {

    if (err) {

      console.log(err);

      return res.status(500).json({

        success: false,
        message: 'Gagal ambil data barang'

      });

    }

    res.json({

      success: true,
      data: result

    });

  });

});

// =====================================
// DETAIL BARANG
// =====================================

app.get('/api/barang/:id', (req, res) => {

  const { id } = req.params;

  const sql = `

    SELECT
      *,
      (stok_gudang + stok_rak)
      AS total_stok

    FROM barangs

    WHERE id = ?

  `;

  db.query(sql, [id], (err, result) => {

    if (err) {

      console.log(err);

      return res.status(500).json({

        success: false,
        message: 'Gagal ambil detail barang'

      });

    }

    res.json(result[0]);

  });

});

// =====================================
// TAMBAH PEMESANAN BARANG
// =====================================

app.post('/api/pemesanan', (req, res) => {

  const {

  barang_id,

  jumlah_pesan,

  nama_supplier

} = req.body;

  console.log('PEMESANAN MASUK');

  const sql = `

  INSERT INTO pemesanan_barang
  (
    barang_id,
    jumlah_pesan,
    nama_supplier,
    status,
    created_at
  )

  VALUES (?, ?, ?, 'dikirim', NOW())

`;

  db.query(

    sql,

    [
  barang_id,
  jumlah_pesan,
  nama_supplier
],

    (err, result) => {

      if (err) {

        console.log(err);

        return res.status(500).json({

          success: false,
          message: 'Gagal menambah pemesanan'

        });

      }

      // =====================================
      // SIMPAN NOTIFIKASI
      // =====================================

      console.log('NOTIF MAU DISIMPAN');

      const sqlNotif = `

  INSERT INTO notifications
  (
    title,
    message,
    is_read,
    created_at
  )

  VALUES (?, ?, ?, NOW())

`;

      db.query(

  sqlNotif,

  [

    'Barang Masuk Baru',

    `Ada pemesanan barang sebanyak ${jumlah_pesan}`,

    0

  ],

  (errNotif, resultNotif) => {

    if (errNotif) {

      console.log(
        'ERROR NOTIF:',
        errNotif
      );

      return res.status(500).json({

        success: false,
        message: 'Gagal simpan notif'

      });

    }

    console.log(
      'NOTIF BERHASIL:',
      resultNotif
    );

    res.json({

      success: true,
      message: 'Pemesanan berhasil ditambahkan'

    });

  }

);

    }

  );

});

// =====================================
// AMBIL DATA PEMESANAN
// =====================================

app.get('/api/pemesanan', (req, res) => {

  const sql = `

    SELECT 
      pemesanan_barang.*,
      barangs.nama_barang,
      barangs.kode_barang,
      barangs.satuan

    FROM pemesanan_barang

    LEFT JOIN barangs 
      ON pemesanan_barang.barang_id = barangs.id

    ORDER BY pemesanan_barang.id DESC

  `;

  db.query(sql, (err, result) => {

    if (err) {

      console.log(err);

      return res.status(500).json({

        success: false,
        message: 'Gagal mengambil data pemesanan'

      });

    }

    res.json({

      success: true,
      data: result

    });

  });

});
// =====================================
// VERIFIKASI BARANG MASUK
// =====================================

app.post('/api/verifikasi-barang', (req, res) => {

  const {
    user_id,
    pemesanan_id,
    barang_id,
    qty_diterima,
    status,
    catatan
  } = req.body;

  // ===============================
  // START TRANSACTION
  // ===============================

  db.beginTransaction((errTrans) => {

    if (errTrans) {

      console.log(errTrans);

      return res.status(500).json({
        success: false,
        message: 'Gagal memulai transaction'
      });

    }

    // ===============================
    // CEK STOK AWAL
    // ===============================

    const sqlCek = `
      SELECT
      total_stok,
      stok_gudang,
      stok_rak
      FROM barangs
      WHERE id = ?
       `;

    db.query(

      sqlCek,

      [barang_id],

      (errCek, resultCek) => {

        if (errCek) {

          return db.rollback(() => {

            console.log(errCek);

            res.status(500).json({
              success: false,
              message: 'Gagal cek stok'
            });

          });

        }

        if (resultCek.length == 0) {

          return db.rollback(() => {

            res.status(404).json({
              success: false,
              message: 'Barang tidak ditemukan'
            });

          });

        }

        const totalSebelum =
  Number(resultCek[0].stok_gudang)
  +
  Number(resultCek[0].stok_rak); 

        const gudangSebelum =
          resultCek[0].stok_gudang;

        const rakSebelum =
          resultCek[0].stok_rak;

        // ===============================
        // UPDATE STOK JIKA DITERIMA
        // ===============================

        const prosesUpdateStok = (callback) => {

          if (status != 'diterima') {

            return callback();

          }

          const sqlTambahStok = `
           UPDATE barangs
           SET stok_gudang =
          stok_gudang + ?
          WHERE id = ?
          `;

          db.query(

            sqlTambahStok,

            [qty_diterima, barang_id],

            (errUpdate) => {

              if (errUpdate) {

                return db.rollback(() => {

                  console.log(errUpdate);

                  res.status(500).json({
                    success: false,
                    message: 'Gagal update stok'
                  });

                });

              }

              callback();

            }

          );

        };

        // ===============================
        // LANJUT UPDATE STATUS
        // ===============================

        prosesUpdateStok(() => {

          const sqlUpdate = `
            UPDATE pemesanan_barang
            SET
              status = ?,
              qty_diterima = ?,
              catatan = ?,
              verified_at = NOW()
            WHERE id = ?
          `;

          db.query(

            sqlUpdate,

            [
              status,
              qty_diterima,
              catatan,
              pemesanan_id
            ],

            (errUpdate2) => {

              if (errUpdate2) {

                return db.rollback(() => {

                  console.log(errUpdate2);

                  res.status(500).json({
                    success: false,
                    message: 'Gagal update verifikasi'
                  });

                });

              }

              // ===============================
              // HITUNG STOK SESUDAH
              // ===============================

              const totalSesudah =

               status == 'diterima'
                ? totalSebelum + Number(qty_diterima)
               : totalSebelum;

              const gudangSesudah =

                status == 'diterima'
                ? gudangSebelum + Number(qty_diterima)
                : gudangSebelum;

              const rakSesudah =
                rakSebelum;

              // ===============================
// SIMPAN TRANSAKSI
// ===============================

const sqlTransaksi = `

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

  VALUES (?,?, ?, ?, ?, ?, ?,?,?,?,?, NOW(), NOW())

`;

db.query(

  sqlTransaksi,

  
    [
  user_id,

  status == 'diterima'
    ? 'barang_masuk'
    : 'barang_ditolak',

  barang_id,

  qty_diterima,

  // TOTAL
  totalSebelum,
  totalSesudah,

  // GUDANG
  gudangSebelum,
  gudangSesudah,

  // RAK
  rakSebelum,
  rakSesudah,

  // KETERANGAN
  catatan || (
    status == 'diterima'
      ? 'Barang masuk diverifikasi'
      : 'Barang ditolak'
  )

],

  (errTransaksi) => {

    if (errTransaksi) {

      return db.rollback(() => {

        console.log(errTransaksi);

        res.status(500).json({

          success: false,

          message:
          'Gagal simpan transaksi'

        });

      });

    }

    // ===============================
    // COMMIT
    // ===============================

    db.commit((errCommit) => {

      if (errCommit) {

        return db.rollback(() => {

          console.log(errCommit);

          res.status(500).json({

            success: false,

            message:
            'Gagal commit transaction'

          });

        });

      }

      // ===============================
      // SAVE SNAPSHOT
      // ===============================

      saveStockSnapshot();

      // ===============================
      // UPDATE NOTIF
      // ===============================

      const sqlUpdateNotif = `

        UPDATE notifications

        SET is_read = 1

        WHERE is_read = 0

      `;

      db.query(sqlUpdateNotif);

      // ===============================
      // RESPONSE
      // ===============================

      res.json({

        success: true,

        message:
        'Verifikasi barang berhasil'

      });

    });

  }

);
            }

          );

        });

      }

    );

  });

});
// =====================================
// BARANG KELUAR
// =====================================

app.post('/api/barang-keluar', (req, res) => {

  db.beginTransaction((errTrans) => {

    if (errTrans) {

      console.log(errTrans);

      return res.status(500).json({
        success: false,
        message: 'Gagal memulai transaction'
      });

    }

    // =====================================
    // BODY
    // =====================================

    const {
      user_id,
      barang_id,
      qty_keluar,
      tujuan,
      catatan
    } = req.body;

    // =====================================
    // CEK STOK
    // =====================================

    const sqlCek = `
      SELECT *
      FROM barangs
      WHERE id = ?
    `;

    db.query(

      sqlCek,

      [barang_id],

      (errCek, resultCek) => {

        if (errCek) {

          return db.rollback(() => {

            console.log(errCek);

            res.status(500).json({
              success: false,
              message: 'Gagal cek stok'
            });

          });

        }

        // barang tidak ditemukan

        if (resultCek.length == 0) {

          return db.rollback(() => {

            res.status(404).json({
              success: false,
              message: 'Barang tidak ditemukan'
            });

          });

        }

        const barang = resultCek[0];
        const totalSebelum =
  Number(barang.stok_gudang)
  +
  Number(barang.stok_rak);

const gudangSebelum =
  barang.stok_gudang;

const rakSebelum =
  barang.stok_rak;

        const stokSebelum =
  rakSebelum;

        // =====================================
        // VALIDASI STOK
        // =====================================

        if (qty_keluar > stokSebelum) {

          return db.rollback(() => {

            res.status(400).json({
              success: false,
              message: 'Stok tidak mencukupi'
            });

          });

        }

        // =====================================
        // HITUNG STOK BARU
        // =====================================

        const stokSesudah =
          stokSebelum - Number(qty_keluar);

          const totalSesudah =
  totalSebelum - Number(qty_keluar);

const gudangSesudah =
  gudangSebelum;

const rakSesudah =
  stokSesudah;

        // =====================================
        // UPDATE STOK
        // =====================================

        const sqlUpdateStok = `
          UPDATE barangs
          SET stok_rak = ?
          WHERE id = ?
        `;

        db.query(

          sqlUpdateStok,

          [
            stokSesudah,
            barang_id
          ],

          (errUpdate) => {

            if (errUpdate) {

              return db.rollback(() => {

                console.log(errUpdate);

                res.status(500).json({
                  success: false,
                  message: 'Gagal update stok'
                });

              });

            }

            // =====================================
            // SIMPAN BARANG KELUAR
            // =====================================

            const sqlBarangKeluar = `
              INSERT INTO barang_keluar
              (
                barang_id,
                qty_keluar,
                tujuan,
                catatan
              )
              VALUES (?, ?, ?, ?)
            `;

            db.query(

              sqlBarangKeluar,

              [
                barang_id,
                qty_keluar,
                tujuan,
                catatan
              ],

              (errInsert) => {

                if (errInsert) {

                  return db.rollback(() => {

                    console.log(errInsert);

                    res.status(500).json({
                      success: false,
                      message: 'Gagal simpan barang keluar'
                    });

                  });

                }

                // =====================================
                // INVENTORY HISTORY
                // =====================================

                const sqlHistory = `
                  INSERT INTO inventory_history
                  (
                    barang_id,
                    tipe_transaksi,
                    qty,
                    stok_sebelum,
                    stok_sesudah,
                    keterangan
                  )
                  VALUES (?, ?, ?, ?, ?, ?)
                `;

                db.query(

                  sqlHistory,

                  [
                    barang_id,
                    'barang_keluar',
                    qty_keluar,
                    stokSebelum,
                    stokSesudah,
                    catatan || 'Barang keluar'
                  ],

                  (errHistory) => {

                    if (errHistory) {

                      return db.rollback(() => {

                        console.log(errHistory);

                        res.status(500).json({
                          success: false,
                          message: 'Gagal simpan history'
                        });

                      });

                    }

                    // =====================================
                    // SIMPAN KE TRANSAKSIS
                    // =====================================

                    const sqlTransaksi = `
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
  VALUES (?,?, ?, ?, ?, ?, ?,?,?,?,?, NOW(), NOW())
                    `;

                    db.query(

                      sqlTransaksi,

                      [
  user_id,

  'barang_keluar',

  barang_id,

  qty_keluar,

  // TOTAL
  totalSebelum,
  totalSesudah,

  // GUDANG
  gudangSebelum,
  gudangSesudah,

  // RAK
  rakSebelum,
  rakSesudah,

  // KETERANGAN
  tujuan
],

                      (errTransaksi) => {

                        if (errTransaksi) {

                          return db.rollback(() => {

                            console.log(errTransaksi);

                            res.status(500).json({
                              success: false,
                              message: 'Gagal simpan transaksi'
                            });

                          });

                        }

                        // =====================================
                        // COMMIT
                        // =====================================

                        db.commit((errCommit) => {

                          if (errCommit) {

                            return db.rollback(() => {

                              console.log(errCommit);

                              res.status(500).json({
                                success: false,
                                message: 'Gagal commit'
                              });

                            });

                          }

                          // =====================================
                          // SNAPSHOT
                          // =====================================

                          saveStockSnapshot();

                          // =====================================
                          // RESPONSE
                          // =====================================

                          res.json({

                            success: true,
                            message: 'Barang berhasil dikeluarkan'

                          });

                        });

                      }

                    );

                  }

                );

              }

            );

          }

        );

      }

    );

  });

});

// =====================================
// MUTASI BARANG
// =====================================

app.post('/api/mutasi-barang', (req, res) => {

  db.beginTransaction((errTrans) => {

    if (errTrans) {

      console.log(errTrans);

      return res.status(500).json({
        success: false,
        message: 'Gagal memulai transaction'
      });

    }

    // =====================================
    // BODY
    // =====================================

    const {
      user_id,
      barang_id,
      qty_mutasi,
      lokasi_asal,
      lokasi_tujuan,
      catatan

    } = req.body;

    // =====================================
    // VALIDASI
    // =====================================

    if (
      !barang_id ||
      !qty_mutasi ||
      !lokasi_asal ||
      !lokasi_tujuan
    ) {

      return res.status(400).json({

        success: false,
        message: 'Data belum lengkap'

      });

    }

    // =====================================
    // CEK BARANG
    // =====================================

    const sqlCek = `
      SELECT *
      FROM barangs
      WHERE id = ?
    `;

    db.query(

      sqlCek,

      [barang_id],

      (errCek, resultCek) => {

        if (errCek) {

          return db.rollback(() => {

            console.log(errCek);

            res.status(500).json({
              success: false,
              message: 'Gagal cek barang'
            });

          });

        }

        // barang tidak ditemukan

        if (resultCek.length == 0) {

          return db.rollback(() => {

            res.status(404).json({
              success: false,
              message: 'Barang tidak ditemukan'
            });

          });

        }

        const barang =
          resultCek[0];

        const stokGudang =
          barang.stok_gudang;

          const totalSebelum =
  Number(barang.stok_gudang)
  +
  Number(barang.stok_rak);

        const stokRak =
          barang.stok_rak || 0;

        // =====================================
        // VALIDASI STOK
        // =====================================

        if (qty_mutasi > stokGudang) {

          return db.rollback(() => {

            res.status(400).json({
              success: false,
              message: 'Stok gudang tidak mencukupi'
            });

          });

        }

        // =====================================
        // HITUNG STOK BARU
        // =====================================

        const stokGudangBaru =
          stokGudang - Number(qty_mutasi);

        const stokRakBaru =
          stokRak + Number(qty_mutasi);

          const totalSesudah =
  totalSebelum;

        // =====================================
        // UPDATE STOK
        // =====================================

        const sqlUpdateStok = `
          UPDATE barangs
          SET
            stok_gudang = ?,
            stok_rak = ?,
            lokasi_rak = ?
          WHERE id = ?
        `;

        db.query(

          sqlUpdateStok,

          [
            stokGudangBaru,
            stokRakBaru,
            lokasi_tujuan,
            barang_id
          ],

          (errUpdate) => {

            if (errUpdate) {

              return db.rollback(() => {

                console.log(errUpdate);

                res.status(500).json({
                  success: false,
                  message: 'Gagal update stok'
                });

              });

            }

            // =====================================
            // SIMPAN MUTASI
            // =====================================

            const sqlInsert = `
              INSERT INTO mutasi_barang
              (
                barang_id,
                qty_mutasi,
                lokasi_asal,
                lokasi_tujuan,
                catatan
              )
              VALUES (?, ?, ?, ?, ?)
            `;

            db.query(

              sqlInsert,

              [

                barang_id,
                qty_mutasi,
                lokasi_asal,
                lokasi_tujuan,
                catatan

              ],

              (errInsert) => {

                if (errInsert) {

                  return db.rollback(() => {

                    console.log(errInsert);

                    res.status(500).json({
                      success: false,
                      message: 'Gagal simpan mutasi'
                    });

                  });

                }

                // =====================================
                // HISTORY
                // =====================================

                const sqlHistory = `
                  INSERT INTO inventory_history
                  (
                    barang_id,
                    tipe_transaksi,
                    qty,
                    stok_sebelum,
                    stok_sesudah,
                    keterangan
                  )
                  VALUES (?, ?, ?, ?, ?, ?)
                `;

                db.query(

                  sqlHistory,

                  [
                    barang_id,
                    'mutasi',
                    qty_mutasi,
                    stokGudang,
                    stokGudangBaru,
                    `Mutasi dari ${lokasi_asal} ke ${lokasi_tujuan}`
                  ],

                  (errHistory) => {

                    if (errHistory) {

                      return db.rollback(() => {

                        console.log(errHistory);

                        res.status(500).json({
                          success: false,
                          message: 'Gagal simpan history'
                        });

                      });

                    }

                    // =====================================
                    // TRANSAKSI
                    // =====================================

                    const sqlTransaksi = `
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

  VALUES (?,?, ?, ?, ?, ?, ?,?,?,?,?, NOW(), NOW())
                    `;

                    db.query(

                      sqlTransaksi,

                      [
  user_id,

  'mutasi',

  barang_id,

  qty_mutasi,

  // TOTAL
  totalSebelum,
  totalSesudah,

  // GUDANG
  stokGudang,
  stokGudangBaru,

  // RAK
  stokRak,
  stokRakBaru,

  // KETERANGAN
  `Mutasi ke ${lokasi_tujuan}`
],

                      (errTransaksi) => {

                        if (errTransaksi) {

                          return db.rollback(() => {

                            console.log(errTransaksi);

                            res.status(500).json({
                              success: false,
                              message: 'Gagal simpan transaksi'
                            });

                          });

                        }

                        // =====================================
                        // COMMIT
                        // =====================================

                        db.commit((errCommit) => {

                          if (errCommit) {

                            return db.rollback(() => {

                              console.log(errCommit);

                              res.status(500).json({
                                success: false,
                                message: 'Gagal commit'
                              });

                            });

                          }

                          // =====================================
                          // SNAPSHOT
                          // =====================================

                          saveStockSnapshot();

                          // =====================================
                          // RESPONSE
                          // =====================================

                          res.json({

                            success: true,
                            message: 'Mutasi barang berhasil'

                          });

                        });

                      }

                    );

                  }

                );

              }

            );

          }

        );

      }

    );

  });

});

// =====================================
// DASHBOARD ANALYTICS
// =====================================

app.get('/api/dashboard-stock', (req, res) => {

  // =====================================
  // TOTAL BARANG
  // =====================================

  const sqlTotalBarang = `
    SELECT COUNT(*) AS total_barang
    FROM barangs
  `;

  // =====================================
  // TOTAL STOK
  // =====================================

  const sqlTotalStok = `
    SELECT
      SUM(stok_gudang + stok_rak)
      AS total_stok
    FROM barangs
  `;

  // =====================================
  // LOW STOCK
  // =====================================

  const sqlLowStock = `
    SELECT COUNT(*) AS low_stock
    FROM barangs
    WHERE (stok_gudang + stok_rak)
    < stok_minimum
  `;

  // =====================================
  // TOTAL BARANG MASUK
  // =====================================

  const sqlBarangMasuk = `
    SELECT COUNT(*) AS barang_masuk
    FROM transaksis
    WHERE jenis = 'barang_masuk'
  `;

  // =====================================
  // TOTAL BARANG KELUAR
  // =====================================

  const sqlBarangKeluar = `
    SELECT COUNT(*) AS barang_keluar
    FROM transaksis
    WHERE jenis = 'barang_keluar'
  `;

  // =====================================
  // TOTAL MUTASI
  // =====================================

  const sqlMutasi = `
    SELECT COUNT(*) AS mutasi
    FROM transaksis
    WHERE jenis = 'mutasi'
  `;

  // =====================================
  // TOTAL BARANG DITOLAK
  // =====================================

  const sqlBarangDitolak = `
    SELECT COUNT(*) AS barang_ditolak
    FROM transaksis
    WHERE jenis = 'barang_ditolak'
  `;

  // =====================================
  // EXECUTE QUERY
  // =====================================

  db.query(sqlTotalBarang, (err1, totalBarang) => {

    if (err1) {

      console.log(err1);

      return res.status(500).json({
        success: false
      });

    }

    db.query(sqlTotalStok, (err2, totalStok) => {

      if (err2) {

        console.log(err2);

        return res.status(500).json({
          success: false
        });

      }

      db.query(sqlLowStock, (err3, lowStock) => {

        if (err3) {

          console.log(err3);

          return res.status(500).json({
            success: false
          });

        }

        db.query(sqlBarangMasuk, (err4, barangMasuk) => {

          if (err4) {

            console.log(err4);

            return res.status(500).json({
              success: false
            });

          }

          db.query(sqlBarangKeluar, (err5, barangKeluar) => {

            if (err5) {

              console.log(err5);

              return res.status(500).json({
                success: false
              });

            }

            db.query(sqlMutasi, (err6, mutasi) => {

              if (err6) {

                console.log(err6);

                return res.status(500).json({
                  success: false
                });

              }

              // =====================================
              // BARANG DITOLAK
              // =====================================

              db.query(sqlBarangDitolak, (err7, barangDitolak) => {

                if (err7) {

                  console.log(err7);

                  return res.status(500).json({
                    success: false
                  });

                }

                // =====================================
                // RESPONSE
                // =====================================

                res.json({

                  success: true,

                  data: {

                    total_barang:
                      totalBarang[0].total_barang || 0,

                    total_stok:
                      totalStok[0].total_stok || 0,

                    low_stock:
                      lowStock[0].low_stock || 0,

                    barang_masuk:
                      barangMasuk[0].barang_masuk || 0,

                    barang_keluar:
                      barangKeluar[0].barang_keluar || 0,

                    mutasi:
                      mutasi[0].mutasi || 0,

                    barang_ditolak:
                      barangDitolak[0].barang_ditolak || 0

                  }

                });

              });

            });

          });

        });

      });

    });

  });

});
// HISTORY TRANSAKSI fitur history

app.get('/api/inventory-history', (req, res) => {

  const sql = `
    SELECT
      transaksis.*,
      barangs.nama_barang,
      barangs.kode_barang
    FROM transaksis
    JOIN barangs
      ON transaksis.barang_id = barangs.id
    ORDER BY transaksis.created_at DESC
  `;

  db.query(sql, (err, result) => {

    if (err) {

      console.log(err);

      return res.status(500).json({
        success: false,
        message: 'Gagal mengambil history transaksi'
      });

    }

    res.json({
      success: true,
      data: result
    });

  });

});

// =====================================
// GRAFIK PERUBAHAN STOK
// =====================================

app.get('/api/stock-line-chart', (req, res) => {

  const bulan =
    parseInt(req.query.bulan);

  const minggu =
    parseInt(req.query.minggu);

  const tahun =
    parseInt(req.query.tahun);

  // =====================================
  // VALIDASI
  // =====================================

  if (!bulan || !minggu || !tahun) {

    return res.status(400).json({

      success: false,
      message: 'Parameter tidak lengkap'

    });

  }

  // =====================================
  // RANGE MINGGU
  // =====================================

  let startDay = 1;
  let endDay = 7;

  if (minggu === 2) {

    startDay = 8;
    endDay = 14;

  }

  else if (minggu === 3) {

    startDay = 15;
    endDay = 21;

  }

  else if (minggu === 4) {

    startDay = 22;
    endDay = 31;

  }

  // =====================================
  // QUERY
  // =====================================

  const sql = `

    SELECT

      DATE(created_at) AS tanggal,

      MAX(total_stok) AS total_stok

    FROM stock_snapshots

    WHERE YEAR(created_at) = ?
    AND MONTH(created_at) = ?
    AND DAY(created_at)
    BETWEEN ? AND ?

    GROUP BY DATE(created_at)

    ORDER BY DATE(created_at) ASC

  `;

  db.query(

    sql,

    [
      tahun,
      bulan,
      startDay,
      endDay
    ],

    (err, result) => {

      if (err) {

        console.log(err);

        return res.status(500).json({

          success: false,
          message: 'Gagal mengambil grafik stok'

        });

      }

      res.json({

        success: true,

        data: result

      });

    }

  );

});

// =====================================
// GET NOTIFICATIONS
// =====================================

app.get('/api/notification', (req, res) => {

  const sql = `

    SELECT *

    FROM notifications

    ORDER BY created_at DESC

    LIMIT 10

  `;

  db.query(sql, (err, result) => {

    if (err) {

      console.log(err);

      return res.status(500).json({

        success: false

      });

    }

    res.json({

      success: true,
      data: result

    });

  });

});

// =====================================
// NOTIFICATION COUNT
// =====================================

app.get('/api/notification-count', (req, res) => {

  const sql = `

    SELECT COUNT(*) as total

    FROM notifications

    WHERE is_read = 0

  `;

  db.query(sql, (err, result) => {

    if (err) {

      console.log(err);

      return res.status(500).json({

        success: false

      });

    }

    res.json({

      total: result[0].total

    });

  });

});

app.get('/test-notif', (req, res) => {

  const sqlNotif = `
    INSERT INTO notifications
    (
      title,
      message,
      is_read,
      created_at
    )

    VALUES (?, ?, ?, NOW())
  `;

  db.query(

    sqlNotif,

    [

      'TEST',

      'TEST NOTIF',

      0

    ],

    (err, result) => {

      console.log(err);

      console.log(result);

      res.json({

        success: true

      });

    }

  );

});

// ================= START SERVER =================

app.listen(3000, () => {
  console.log('🚀 Server jalan di http://localhost:3000');
});
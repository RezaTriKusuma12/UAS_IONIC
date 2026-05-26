import {
  Component
} from '@angular/core';

import {
  MutasiBarangService
} from '../services/mutasi-barang';

@Component({
  selector: 'app-mutasi-barang',
  templateUrl: './mutasi-barang.page.html',
  styleUrls: ['./mutasi-barang.page.scss'],
  standalone: false
})

export class MutasiBarangPage {

  barangList: any[] = [];

  selectedBarang: any;

  qtyMutasi: number = 0;

  lokasiAsal: string = '';

  lokasiTujuan: string = '';

  catatan: string = '';

  constructor(

    private mutasiBarangService:
    MutasiBarangService

  ) {}

  // =====================================
  // REFRESH PAGE
  // =====================================

  ionViewWillEnter() {

    this.loadBarang();

  }

  // =====================================
  // CLEANUP
  // =====================================

  ionViewWillLeave() {

    this.selectedBarang = null;

    this.qtyMutasi = 0;

    this.lokasiAsal = '';

    this.lokasiTujuan = '';

    this.catatan = '';

  }

  // =====================================
  // LOAD BARANG
  // =====================================

  loadBarang() {

    this.mutasiBarangService
    .getBarang()

    .subscribe({

      next: (res: any) => {

        this.barangList =
          res.data;

      },

      error: (err) => {

        console.log(err);

        alert(
          'Gagal load barang'
        );

      }

    });

  }

  // =====================================
  // SUBMIT MUTASI
  // =====================================

  submitMutasi() {

  if (!this.selectedBarang) {

    alert(
      'Pilih barang terlebih dahulu'
    );

    return;

  }

  if (this.qtyMutasi <= 0) {

    alert(
      'Qty mutasi tidak valid'
    );

    return;

  }

  if (
    this.qtyMutasi >
    this.selectedBarang.stok_gudang
  ) {

    alert(
      'Stok gudang tidak cukup'
    );

    return;

  }

  if (
    !this.lokasiAsal ||
    !this.lokasiTujuan
  ) {

    alert(
      'Lokasi belum lengkap'
    );

    return;

  }

  // =========================
  // AMBIL USER LOGIN
  // =========================

  const user = JSON.parse(
    localStorage.getItem('user') || '{}'
  );

  const body = {

    user_id: user.id,

    barang_id:
    this.selectedBarang.id,

    qty_mutasi:
    this.qtyMutasi,

    lokasi_asal:
    this.lokasiAsal,

    lokasi_tujuan:
    this.lokasiTujuan,

    catatan:
    this.catatan

  };

  this.mutasiBarangService
  .mutasiBarang(body)

  .subscribe({

    next: (res: any) => {

      alert(res.message);

      this.selectedBarang = null;

      this.qtyMutasi = 0;

      this.lokasiAsal = '';

      this.lokasiTujuan = '';

      this.catatan = '';

    },

    error: (err) => {

      console.log(err);

      alert(

        err?.error?.message ||

        'Terjadi kesalahan'

      );

    }

  });

}

}
import {
  Component
} from '@angular/core';

import {
  BarangKeluarService
} from '../services/barang-keluar';

@Component({
  selector: 'app-barang-keluar',
  templateUrl: './barang-keluar.page.html',
  styleUrls: ['./barang-keluar.page.scss'],
  standalone: false
})

export class BarangKeluarPage {

  // =====================================
  // DATA BARANG
  // =====================================

  barangList: any[] = [];

  barang_id: any = '';

  barangDipilih: any = null;

  // =====================================
  // FORM
  // =====================================

  qtyKeluar: number = 0;

  tujuanRak: string = '';

  catatan: string = '';

  constructor(

    private barangKeluarService:
    BarangKeluarService

  ) {}

  // =====================================
  // LOAD PAGE
  // =====================================

  ionViewWillEnter() {

    this.loadBarang();

  }

  // =====================================
  // GET BARANG
  // =====================================

  loadBarang() {

    this.barangKeluarService
    .getBarang()

    .subscribe({

      next: (res: any) => {

        this.barangList =
          res.data;

      },

      error: (err) => {

        console.log(err);

      }

    });

  }

  // =====================================
  // PILIH BARANG
  // =====================================

  pilihBarang() {

    this.barangDipilih =
      this.barangList.find(

        x => x.id == this.barang_id

      );

  }

  // =====================================
  // SUBMIT BARANG KELUAR
  // =====================================

  submitBarangKeluar() {

    // =====================================
    // VALIDASI
    // =====================================

    if (!this.barangDipilih) {

      alert('Pilih barang');

      return;

    }

    if (this.qtyKeluar <= 0) {

      alert('Qty keluar tidak valid');

      return;

    }

    // =====================================
    // AMBIL USER LOGIN
    // =====================================

    const user = JSON.parse(

      localStorage.getItem('user') || '{}'

    );

    // =====================================
    // BODY REQUEST
    // =====================================

    const body = {

      user_id: user.id,

      barang_id:
      this.barangDipilih.id,

      qty_keluar:
      Number(this.qtyKeluar),

      tujuan_rak:
      this.tujuanRak,

      catatan:
      this.catatan

    };

    console.log(body);

    // =====================================
    // REQUEST API
    // =====================================

    this.barangKeluarService

    .barangKeluar(body)

    .subscribe({

      next: (res: any) => {

        console.log(res);

        alert(res.message);

        // =====================================
        // RESET FORM
        // =====================================

        this.qtyKeluar = 0;

        this.tujuanRak = '';

        this.catatan = '';

        // =====================================
        // RESET PILIHAN BARANG
        // =====================================

        this.barangDipilih = null;

        this.barang_id = '';

        // =====================================
        // REFRESH DATA BARANG
        // =====================================

        this.loadBarang();

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
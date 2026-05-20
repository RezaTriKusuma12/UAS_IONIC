import { Component, OnInit } from '@angular/core';

import { PemesananService }
from '../services/pemesanan';

import {
  ModalController,
  NavParams
} from '@ionic/angular';

@Component({
  selector: 'app-verifikasi-barang',
  templateUrl: './verifikasi-barang.page.html',
  styleUrls: ['./verifikasi-barang.page.scss'],
  standalone: false
})

export class VerifikasiBarangPage implements OnInit {

  barang: any;

  qtyDiterima: number = 0;

  statusBarang: string = '';

  catatan: string = '';

  constructor(

    private modalCtrl: ModalController,

    private navParams: NavParams,

    private pemesananService: PemesananService

  ) {}

  ngOnInit() {

    this.barang =
      this.navParams.get('barang');

  }

  // =========================
  // PILIH STATUS
  // =========================

  pilihStatus(status: string) {

    this.statusBarang = status;

    console.log(this.statusBarang);

  }

  // =========================
  // CLOSE MODAL
  // =========================

  closeModal() {

    this.modalCtrl.dismiss();

  }

  // =========================
  // SUBMIT VERIFIKASI
  // =========================

  submitVerifikasi() {

  console.log('STATUS:', this.statusBarang);

  // =========================
  // AMBIL USER LOGIN
  // =========================

  const user = JSON.parse(
    localStorage.getItem('user') || '{}'
  );

  const body = {

    user_id: user.id,

    pemesanan_id: this.barang.id,

    barang_id: this.barang.barang_id,

    qty_diterima: this.qtyDiterima,

    status: this.statusBarang,

    catatan: this.catatan

  };

  console.log(body);

  this.pemesananService
    .verifikasiBarang(body)
    .subscribe({

      next: (res: any) => {

        console.log(res);

        alert('Verifikasi berhasil');

        this.modalCtrl.dismiss(true);

      },

      error: (err) => {

        console.log(err);

        alert('Gagal verifikasi');

      }

    });

}
}
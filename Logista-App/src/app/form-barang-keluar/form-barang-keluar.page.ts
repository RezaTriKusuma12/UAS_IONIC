import { Component, OnInit } from '@angular/core';

import {
  ModalController,
  NavParams
} from '@ionic/angular';

import { BarangKeluarService }
from '../services/barang-keluar';

@Component({
  selector: 'app-form-barang-keluar',
  templateUrl: './form-barang-keluar.page.html',
  styleUrls: ['./form-barang-keluar.page.scss'],
  standalone: false
})

export class FormBarangKeluarPage
implements OnInit {

  barang: any;

  qtyKeluar: number = 0;

  tujuanRak: string = '';

  catatan: string = '';

  constructor(

    private modalCtrl: ModalController,

    private navParams: NavParams,

    private barangKeluarService:
    BarangKeluarService

  ) {}

  ngOnInit() {

    this.barang =
      this.navParams.get('barang');

  }

  // =========================
  // CLOSE MODAL
  // =========================

  closeModal() {

    this.modalCtrl.dismiss();

  }

  // =========================
  // SUBMIT BARANG KELUAR
  // =========================

 submitBarangKeluar() {

  // =========================
  // AMBIL USER LOGIN
  // =========================

  const user = JSON.parse(
    localStorage.getItem('user') || '{}'
  );

  const body = {

    user_id: user.id,

    barang_id: this.barang.id,

    qty_keluar: this.qtyKeluar,

    tujuan_rak: this.tujuanRak,

    catatan: this.catatan

  };

  console.log(body);

  this.barangKeluarService
    .barangKeluar(body)
    .subscribe({

      next: (res: any) => {

        console.log(res);

        alert(res.message);

        this.modalCtrl.dismiss(true);

      },

      error: (err) => {

        console.log(err);

        alert(err.error.message);

      }

    });

}

}
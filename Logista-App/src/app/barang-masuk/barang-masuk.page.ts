import {
  Component
} from '@angular/core';

import {
  PemesananService
} from '../services/pemesanan';

import {
  ModalController
} from '@ionic/angular';

import {
  VerifikasiBarangPage
} from '../verifikasi-barang/verifikasi-barang.page';

@Component({
  selector: 'app-barang-masuk',
  templateUrl: './barang-masuk.page.html',
  styleUrls: ['./barang-masuk.page.scss'],
  standalone: false
})

export class BarangMasukPage {

  pemesananList: any[] = [];

  qtyDiterima: number = 0;

  statusBarang: string = '';

  catatan: string = '';

  selectedBarang: any = null;

  constructor(

    private pemesananService:
    PemesananService,

    private modalCtrl:
    ModalController

  ) {}

  // =====================================
  // REFRESH PAGE
  // =====================================

  ionViewWillEnter() {

    this.loadPemesanan();

  }

  // =====================================
  // CLEANUP
  // =====================================

  ionViewWillLeave() {

    this.selectedBarang = null;

  }

  // =====================================
  // LOAD PEMESANAN
  // =====================================

  loadPemesanan() {

    this.pemesananService
    .getPemesanan()

    .subscribe({

      next: (res: any) => {

        this.pemesananList =
          res.data;

        this.selectedBarang =
          res.data[0];

      },

      error: (err) => {

        console.log(err);

      }

    });

  }

  // =====================================
  // OPEN VERIFIKASI
  // =====================================

  async openVerifikasi(
    item: any
  ) {

    const modal =
      await this.modalCtrl
      .create({

        component:
        VerifikasiBarangPage,

        componentProps: {

          barang: item

        }

      });

    await modal.present();

    const { data } =
      await modal.onDidDismiss();

    if (data) {

      this.loadPemesanan();

    }

  }

}
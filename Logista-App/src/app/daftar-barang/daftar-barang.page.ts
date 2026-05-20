import { Component }
from '@angular/core';

import {
  BarangService
} from '../services/daftar-barang';

@Component({
  selector: 'app-daftar-barang',
  templateUrl: './daftar-barang.page.html',
  styleUrls: ['./daftar-barang.page.scss'],
  standalone: false
})

export class DaftarBarangPage {

  barangList: any[] = [];

  allBarang: any[] = [];

  constructor(
    private barangService:
    BarangService
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

    this.barangList = [];

  }

  // =====================================
  // LOAD BARANG
  // =====================================

  loadBarang() {

    this.barangService
    .getBarang()

    .subscribe({

      next: (res: any) => {

        this.barangList =
          res.data;

        this.allBarang =
          res.data;

      },

      error: (err) => {

        console.log(err);

      }

    });

  }

  // =====================================
  // SEARCH
  // =====================================

  filterBarang(event: any) {

    const keyword =
      event.target.value
      ?.toLowerCase();

    if (!keyword) {

      this.barangList =
        this.allBarang;

      return;

    }

    this.barangList =
      this.allBarang.filter(
        (item: any) => {

        return (

          item.nama_barang
          .toLowerCase()
          .includes(keyword)

          ||

          item.kode_barang
          .toLowerCase()
          .includes(keyword)

        );

      });

  }

  // =====================================
  // TOGGLE DETAIL
  // =====================================

  toggleDetail(item: any) {

    item.showDetail =
      !item.showDetail;

  }

}
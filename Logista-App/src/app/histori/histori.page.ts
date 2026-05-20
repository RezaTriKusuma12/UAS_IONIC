import {
  Component,
  OnInit,
  OnDestroy
} from '@angular/core';

import {
  NavController
} from '@ionic/angular';

import {
  HistoryService
} from '../services/inventory-history';

@Component({
  selector: 'app-histori',
  templateUrl: './histori.page.html',
  styleUrls: ['./histori.page.scss'],
  standalone: false
})

export class HistoriPage
implements
OnInit,
OnDestroy {

  // =====================================
  // DATA
  // =====================================

  history: any[] = [];

  filteredHistory: any[] = [];

  // =====================================
  // FILTER
  // =====================================

  selectedFilter: string =
    'all';

  searchText: string = '';

  constructor(

    private historyService:
    HistoryService,

    private navCtrl:
    NavController

  ) {}

  // =====================================
  // INIT
  // =====================================

  ngOnInit() {}

  // =====================================
  // SAAT MASUK PAGE
  // =====================================

  ionViewWillEnter() {

    // =========================
    // CEK LOGIN
    // =========================

    const dataUser =
      localStorage.getItem('user');

    // jika belum login
    if (!dataUser) {

      this.navCtrl.navigateRoot(
        '/login'
      );

      return;

    }

    // =========================
    // LOAD HISTORY
    // =========================

    this.loadHistory();

  }

  // =====================================
  // SAAT KELUAR PAGE
  // =====================================

  ionViewWillLeave() {

    // reset search
    this.searchText = '';

    // reset filter
    this.selectedFilter =
      'all';

  }

  // =====================================
  // DESTROY COMPONENT
  // =====================================

  ngOnDestroy() {

    this.history = [];

    this.filteredHistory = [];

  }

  // =====================================
  // LOAD HISTORY
  // =====================================

  loadHistory() {

    this.historyService
    .getHistory()

    .subscribe({

      next: (res: any) => {

        console.log(res);

        this.history =
          res.data;

        this.filteredHistory =
          res.data;

      },

      error: (err) => {

        console.log(err);

      }

    });

  }

  // =====================================
  // SEARCH HISTORY
  // =====================================

  searchHistory(event: any) {

    this.searchText =

      event.target.value
      ?.toLowerCase() || '';

    this.applyFilter();

  }

  // =====================================
  // FILTER HISTORY
  // =====================================

  filterHistory(event: any) {

    this.selectedFilter =

      event.detail.value;

    this.applyFilter();

  }

  // =====================================
  // APPLY FILTER
  // =====================================

  applyFilter() {

    this.filteredHistory =

      this.history.filter(
        (item) => {

        // ===================
        // SEARCH
        // ===================

        const matchSearch =

          item.nama_barang
          .toLowerCase()

          .includes(
            this.searchText
          );

        // ===================
        // FILTER
        // ===================

        const matchFilter =

          this.selectedFilter
          === 'all'

          ||

          item.jenis
          === this.selectedFilter;

        return (
          matchSearch &&
          matchFilter
        );

      });

  }

  // =====================================
  // BADGE COLOR
  // =====================================

  getBadgeColor(type: string) {

    switch(type) {

      case 'barang_masuk':

        return 'success';

      case 'barang_keluar':

        return 'danger';

      case 'mutasi':

        return 'warning';

      case 'barang_ditolak':

        return 'dark';

      default:

        return 'medium';

    }

  }

  // =====================================
  // ICON
  // =====================================

  getIcon(type: string) {

    switch(type) {

      case 'barang_masuk':

        return 'arrow-down-circle';

      case 'barang_keluar':

        return 'arrow-up-circle';

      case 'mutasi':

        return 'swap-horizontal';

      case 'barang_ditolak':

        return 'close-circle';

      default:

        return 'cube';

    }

  }
// =====================================
// FORMAT TOTAL STOK
// =====================================

getTotalStockBefore(item: any): number {

  return item.total_stok_sebelum ?? 0;

}

getTotalStockAfter(item: any): number {

  return item.total_stok_sesudah ?? 0;

}

// =====================================
// FORMAT STOK GUDANG
// =====================================

getGudangBefore(item: any): number {

  return item.stok_gudang_sebelum ?? 0;

}

getGudangAfter(item: any): number {

  return item.stok_gudang_sesudah ?? 0;

}

// =====================================
// FORMAT STOK RAK
// =====================================

getRakBefore(item: any): number {

  return item.stok_rak_sebelum ?? 0;

}

getRakAfter(item: any): number {

  return item.stok_rak_sesudah ?? 0;

}
}
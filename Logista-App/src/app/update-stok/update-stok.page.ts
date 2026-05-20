import {
  Component,
  OnInit,
  AfterViewInit,
  ViewChild,
  ElementRef,
  OnDestroy
} from '@angular/core';

import { HttpClient }
from '@angular/common/http';

import {
  NavController
} from '@ionic/angular';

import Chart from 'chart.js/auto';

@Component({
  selector: 'app-update-stok',
  templateUrl: './update-stok.page.html',
  styleUrls: ['./update-stok.page.scss'],
  standalone: false
})

export class UpdateStokPage
implements
OnInit,
AfterViewInit,
OnDestroy {

  // =====================================
  // DASHBOARD DATA
  // =====================================

  dashboard: any = {};

  // =====================================
  // REALTIME CLOCK
  // =====================================

  currentTime: string = '';

  currentDate: string = '';

  clockInterval: any;

  // =====================================
  // FILTER
  // =====================================

  selectedPeriode =
    'bulanan';

  selectedBulan =
    new Date().getMonth() + 1;

  selectedTahun =
    new Date().getFullYear();

  selectedMinggu =
    1;

  // =====================================
  // CHART
  // =====================================

  @ViewChild('lineChart')
  lineChart!: ElementRef;

  stockChart: any;

  constructor(

    private http: HttpClient,

    private navCtrl:
    NavController

  ) {}

  // =====================================
  // INIT
  // =====================================

  ngOnInit() {}

  // =====================================
  // SAAT PAGE MASUK
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
    // LOAD DASHBOARD
    // =========================

    this.loadDashboard();

    // =========================
    // REALTIME CLOCK
    // =========================

    this.updateClock();

    this.clockInterval =
      setInterval(() => {

        this.updateClock();

      }, 1000);

  }

  // =====================================
  // AFTER VIEW INIT
  // =====================================

  ngAfterViewInit() {

    this.loadStockChart();

  }

  // =====================================
  // SAAT PAGE KELUAR
  // =====================================

  ionViewWillLeave() {

    // stop realtime clock
    clearInterval(
      this.clockInterval
    );

  }

  // =====================================
  // DESTROY COMPONENT
  // =====================================

  ngOnDestroy() {

    // destroy chart
    if (this.stockChart) {

      this.stockChart.destroy();

    }

    // clear interval
    clearInterval(
      this.clockInterval
    );

  }

  // =====================================
  // LOAD DASHBOARD
  // =====================================

  loadDashboard() {

    this.http.get(
      'http://localhost:3000/api/dashboard-stock'
    )

    .subscribe({

      next: (res: any) => {

        console.log(res);

        this.dashboard =
          res.data;

      },

      error: (err) => {

        console.log(err);

      }

    });

  }

  // =====================================
  // LOAD STOCK CHART
  // =====================================

  loadStockChart() {

    // destroy chart lama

    if (this.stockChart) {

      this.stockChart.destroy();

    }

    this.http.get(

`http://localhost:3000/api/stock-line-chart?bulan=${this.selectedBulan}&minggu=${this.selectedMinggu}&tahun=${this.selectedTahun}`

    )

    .subscribe({

      next: (res: any) => {

        const data =
          res.data;

        // =====================
        // LABEL
        // =====================

        const labels =
          data.map((x: any) => {

            return new Date(
              x.tanggal
            )

            .toLocaleDateString(
              'id-ID',
              {

                day: 'numeric',

                month: 'short'

              }
            );

          });

        // =====================
        // STOK
        // =====================

        const stok =
          data.map((x: any) =>

            x.total_stok

          );

        // =====================
        // CREATE CHART
        // =====================

        this.createStockChart(

          labels,

          stok

        );

      },

      error: (err) => {

        console.log(err);

      }

    });

  }

  // =====================================
  // CREATE CHART
  // =====================================

  createStockChart(

    labels: any,

    stok: any

  ) {

    this.stockChart =
      new Chart(

      this.lineChart
      .nativeElement,

      {

        type: 'line',

        data: {

          labels: labels,

          datasets: [

            {

              label:
              'Perubahan Total Stok Gudang',

              data: stok,

              borderWidth: 3,

              tension: 0.4,

              fill: true,

              pointRadius: 5,

              backgroundColor:
              'rgba(76,175,80,0.2)',

              borderColor:
              '#4CAF50'

            }

          ]

        },

        options: {

          responsive: true,

          maintainAspectRatio: false,

          plugins: {

            legend: {

              display: true

            }

          },

          scales: {

            y: {

              beginAtZero: true

            }

          }

        }

      }

    );

  }

  // =====================================
  // FILTER CHART
  // =====================================

  filterChart() {

    this.loadStockChart();

  }

  // =====================================
  // REALTIME CLOCK
  // =====================================

  updateClock() {

    const now =
      new Date();

    // jam realtime

    this.currentTime =

      now.toLocaleTimeString(
        'id-ID'
      );

    // tanggal realtime

    this.currentDate =

      now.toLocaleDateString(
        'id-ID',
        {

          weekday: 'long',

          year: 'numeric',

          month: 'long',

          day: 'numeric'

        }
      );

  }

}
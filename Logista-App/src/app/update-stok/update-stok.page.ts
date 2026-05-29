import {
  Component,
  OnInit,
  AfterViewInit,
  ViewChild,
  ElementRef,
  OnDestroy
} from '@angular/core';

import { HttpClient } from '@angular/common/http';

import { NavController } from '@ionic/angular';

import Chart from 'chart.js/auto';

@Component({
  selector: 'app-update-stok',
  templateUrl: './update-stok.page.html',
  styleUrls: ['./update-stok.page.scss'],
  standalone: false
})
export class UpdateStokPage implements OnInit, AfterViewInit, OnDestroy {

  dashboard: any = {};

  currentTime: string = '';
  currentDate: string = '';
  clockInterval: any;

  selectedPeriode = 'bulanan';
  selectedBulan = new Date().getMonth() + 1;
  selectedTahun = new Date().getFullYear();
  selectedMinggu = 1;

  @ViewChild('lineChart')
  lineChart!: ElementRef<HTMLCanvasElement>;

  stockChart: any;

  private apiUrl = 'https://luminous.my.id/api';

  constructor(
    private http: HttpClient,
    private navCtrl: NavController
  ) {}

  ngOnInit() {}

  ngAfterViewInit() {
    setTimeout(() => {
      this.loadStockChart();
    }, 300);
  }

  ionViewWillEnter() {
    const dataUser = localStorage.getItem('user');

    if (!dataUser) {
      this.navCtrl.navigateRoot('/login');
      return;
    }

    this.loadDashboard();
    this.loadStockChart();

    this.updateClock();

    if (this.clockInterval) {
      clearInterval(this.clockInterval);
    }

    this.clockInterval = setInterval(() => {
      this.updateClock();
    }, 1000);
  }

  ionViewWillLeave() {
    if (this.clockInterval) {
      clearInterval(this.clockInterval);
    }
  }

  ngOnDestroy() {
    if (this.stockChart) {
      this.stockChart.destroy();
    }

    if (this.clockInterval) {
      clearInterval(this.clockInterval);
    }
  }

  loadDashboard() {
    this.http.get(`${this.apiUrl}/dashboard-stock`).subscribe({
      next: (res: any) => {
        console.log(res);
        this.dashboard = res.data || {};
      },
      error: (err) => {
        console.log(err);
      }
    });
  }

  loadStockChart() {
    if (!this.lineChart) {
      return;
    }

    const url =
      `${this.apiUrl}/stock-line-chart?bulan=${this.selectedBulan}&minggu=${this.selectedMinggu}&tahun=${this.selectedTahun}`;

    this.http.get(url).subscribe({
      next: (res: any) => {
        const data = res.data || [];

        const labels = data.map((x: any) => {
          return new Date(x.tanggal).toLocaleDateString('id-ID', {
            day: 'numeric',
            month: 'short'
          });
        });

        const stok = data.map((x: any) => x.total_stok);

        this.createStockChart(labels, stok);
      },
      error: (err) => {
        console.log(err);
      }
    });
  }

  createStockChart(labels: any[], stok: any[]) {
    if (this.stockChart) {
      this.stockChart.destroy();
    }

    const darkMode = this.isDarkMode();

    const textColor = darkMode ? '#f8fafc' : '#0f172a';
    const gridColor = darkMode
      ? 'rgba(148, 163, 184, 0.22)'
      : 'rgba(100, 116, 139, 0.18)';

    this.stockChart = new Chart(
      this.lineChart.nativeElement,
      {
        type: 'line',
        data: {
          labels: labels,
          datasets: [
            {
              label: 'Perubahan Total Stok Gudang',
              data: stok,
              borderWidth: 3,
              tension: 0.4,
              fill: true,
              pointRadius: 5,
              pointHoverRadius: 7,
              backgroundColor: 'rgba(43, 177, 187, 0.18)',
              borderColor: '#2bb1bb',
              pointBackgroundColor: '#2bb1bb',
              pointBorderColor: '#ffffff'
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              display: true,
              labels: {
                color: textColor,
                font: {
                  size: 12,
                  weight: 'bold'
                }
              }
            },
            tooltip: {
              backgroundColor: darkMode ? '#111827' : '#ffffff',
              titleColor: textColor,
              bodyColor: textColor,
              borderColor: darkMode ? '#334155' : '#e2e8f0',
              borderWidth: 1,
              padding: 12,
              displayColors: false
            }
          },
          scales: {
            x: {
              ticks: {
                color: textColor,
                font: {
                  size: 11
                }
              },
              grid: {
                color: gridColor
              }
            },
            y: {
              beginAtZero: true,
              ticks: {
                color: textColor,
                font: {
                  size: 11
                }
              },
              grid: {
                color: gridColor
              }
            }
          }
        }
      }
    );
  }

  filterChart() {
    this.loadStockChart();
  }

  updateClock() {
    const now = new Date();

    this.currentTime = now.toLocaleTimeString('id-ID');

    this.currentDate = now.toLocaleDateString('id-ID', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  }

  isDarkMode(): boolean {
    const bodyDark = document.body.classList.contains('dark');

    const systemDark = window.matchMedia &&
      window.matchMedia('(prefers-color-scheme: dark)').matches;

    return bodyDark || systemDark;
  }

}
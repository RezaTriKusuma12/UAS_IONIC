import { Component, OnInit } from '@angular/core';

import { NavController } from '@ionic/angular';

import { register } from 'swiper/element/bundle';

import { PushNotifications }
from '@capacitor/push-notifications';

import { LocalNotifications }
from '@capacitor/local-notifications';

import { NotificationService }
from '../services/notification';

import { BarangService }
from '../services/daftar-barang';

register();

@Component({
  selector: 'app-home',
  templateUrl: 'home.page.html',
  styleUrls: ['home.page.scss'],
  standalone: false,
})

export class HomePage
implements OnInit {

  // =====================================
  // USER
  // =====================================

  user: any;

  // =====================================
  // NOTIFICATION
  // =====================================

  notificationCount: number = 0;

  showNotification: boolean = false;

  notifications: any[] = [];

  // =====================================
  // SEARCH
  // =====================================

  allBarang: any[] = [];

  searchResults: any[] = [];

  // =====================================
  // PROFILE POPUP
  // =====================================

  showProfile: boolean = false;

  constructor(

    private navCtrl: NavController,

    private notificationService:
    NotificationService,

    private barangService:
    BarangService

  ) {}

  // =====================================
  // INIT
  // =====================================

  ngOnInit() {}

  // =====================================
  // REFRESH SAAT MASUK PAGE
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

    // simpan user
    this.user =
      JSON.parse(dataUser);

    // =========================
    // FIREBASE NOTIFICATION
    // =========================

    this.initPushNotification();

    // =========================
    // LOAD DATA
    // =========================

    this.loadNotificationCount();

    this.loadBarang();

  }

  // =====================================
  // CLEANUP SAAT KELUAR PAGE
  // =====================================

  ionViewWillLeave() {

    this.showNotification = false;

    this.showProfile = false;

  }

  // =====================================
  // FIREBASE PUSH NOTIFICATION
  // =====================================

  async initPushNotification() {

  // =========================
  // REQUEST LOCAL NOTIF
  // =========================

  await LocalNotifications
  .requestPermissions();

  // =========================
  // REQUEST PUSH NOTIF
  // =========================

  const permission =

    await PushNotifications
    .requestPermissions();

  // =========================
  // JIKA DIIZINKAN
  // =========================

  if (
    permission.receive ===
    'granted'
  ) {

    // register firebase
    await PushNotifications
    .register();

  }

  // =================================
  // TOKEN DEVICE
  // =================================

  PushNotifications
  .addListener(

    'registration',

    (token) => {

      console.log(
        'FCM TOKEN:',
        token.value
      );

    }

  );

  // =================================
  // NOTIF DITERIMA
  // =================================

  PushNotifications
  .addListener(

    'pushNotificationReceived',

    async (notification) => {

      console.log(
        'NOTIF MASUK:',
        notification
      );

      // tampil notif lokal
      await LocalNotifications
      .schedule({

        notifications: [

          {

            title:
              notification.title ||

              'Logista',

            body:
              notification.body ||

              'Ada notifikasi baru',

            id:
              new Date().getTime(),

            schedule: {

              at: new Date(
                Date.now() + 1000
              )

            }

          }

        ]

      });

    }

  );

  // =================================
  // NOTIF DIKLIK
  // =================================

  PushNotifications
  .addListener(

    'pushNotificationActionPerformed',

    (notification) => {

      console.log(
        'NOTIF DIKLIK:',
        notification
      );

      this.navCtrl
      .navigateForward(
        '/barang-masuk'
      );

    }

  );

}

  // =====================================
  // LOAD BARANG
  // =====================================

  loadBarang() {

    this.barangService
    .getBarang()

    .subscribe({

      next: (res: any) => {

        this.allBarang =
          res.data;

      },

      error: (err) => {

        console.log(err);

      }

    });

  }

  // =====================================
  // SEARCH BARANG
  // =====================================

  filterBarang(event: any) {

    const keyword =
      event.target.value
      ?.toLowerCase();

    // kosong
    if (!keyword) {

      this.searchResults = [];

      return;

    }

    this.searchResults =
      this.allBarang.filter((item: any) => {

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
  // LOAD NOTIFICATION COUNT
  // =====================================

  loadNotificationCount() {

    this.notificationService
    .getNotificationCount()

    .subscribe({

      next: (res: any) => {

        this.notificationCount =
          res.total;

      },

      error: (err) => {

        console.log(err);

      }

    });

  }

  // =====================================
  // TOGGLE NOTIFICATION
  // =====================================

  toggleNotification() {

    this.showNotification =
      !this.showNotification;

    if (this.showNotification) {

      this.loadNotifications();

    }

  }

  // =====================================
  // LOAD NOTIFICATIONS
  // =====================================

  loadNotifications() {

    this.notificationService
    .getNotifications()

    .subscribe({

      next: (res: any) => {

        this.notifications =
          res.data;

      },

      error: (err) => {

        console.log(err);

      }

    });

  }

  // =====================================
  // OPEN BARANG MASUK
  // =====================================

  openBarangMasuk() {

    this.showNotification = false;

    this.navCtrl.navigateForward(
      '/barang-masuk'
    );

  }

  // =====================================
  // LOGOUT
  // =====================================

  logout() {

    // hapus session
    localStorage.clear();

    // reset navigation
    this.navCtrl.navigateRoot(
      '/login'
    );

  }

  // =====================================
  // NAVIGATION
  // =====================================

  goToBarang() {

    this.navCtrl
    .navigateForward(
      '/daftar-barang'
    );

  }

  goToStok() {

    this.navCtrl
    .navigateForward(
      '/stok-barang'
    );

  }

  goToBarangMasuk() {

    this.navCtrl
    .navigateForward(
      '/barang-masuk'
    );

  }

  goTomutasiBarang() {

    this.navCtrl
    .navigateForward(
      '/mutasi-barang'
    );

  }

  goToHistori() {

    this.navCtrl
    .navigateForward(
      '/histori'
    );

  }

  goToUpdateStok() {

    this.navCtrl
    .navigateForward(
      '/update-stok'
    );

  }

  goToBarangKeluar() {

    this.navCtrl
    .navigateForward(
      '/barang-keluar'
    );

  }

}
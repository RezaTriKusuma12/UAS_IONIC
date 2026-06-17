import { Component, OnInit } from '@angular/core';
import { NavController } from '@ionic/angular';
import { register } from 'swiper/element/bundle';
import { Capacitor } from '@capacitor/core';
import { PushNotifications } from '@capacitor/push-notifications';
import { LocalNotifications } from '@capacitor/local-notifications';

import { NotificationService } from '../services/notification';
import { BarangService } from '../services/daftar-barang';
import { AuthService } from '../services/auth';

register();

@Component({
  selector: 'app-home',
  templateUrl: 'home.page.html',
  styleUrls: ['home.page.scss'],
  standalone: false,
})

export class HomePage implements OnInit {
  user: any = null;

  notificationCount = 0;
  showNotification = false;
  notifications: any[] = [];

  allBarang: any[] = [];
  searchResults: any[] = [];

  showProfile = false;

  private notifInterval: any = null;
  private pushInitialized = false;

  private activityInterval: any = null;
  private statusCheckInterval: any = null;

  constructor(
    private navCtrl: NavController,
    private notificationService: NotificationService,
    private barangService: BarangService,
    private authService: AuthService
  ) {}

  ngOnInit() {}

  ionViewWillEnter() {
    if (!this.loadUserSession()) {
      return;
    }

    this.updateOperatorActivity();
    this.checkAccountStatus();

    this.startActivityInterval();
    this.startStatusCheckInterval();

    this.initPushNotification();
    this.loadInitialData();
    this.startNotificationPolling();
  }

  ionViewWillLeave() {
    this.showNotification = false;
    this.showProfile = false;

    this.stopNotificationPolling();
    this.stopActivityInterval();
    this.stopStatusCheckInterval();
  }

  private loadUserSession(): boolean {
    const dataUser = localStorage.getItem('user');

    if (!dataUser) {
      this.navCtrl.navigateRoot('/login');
      return false;
    }

    try {
      this.user = JSON.parse(dataUser);

      if (this.user?.email) {
        localStorage.setItem('user_email', this.user.email);
      }

      return true;
    } catch (error) {
      localStorage.clear();
      this.navCtrl.navigateRoot('/login');
      return false;
    }
  }

  private checkAccountStatus() {
    const email = localStorage.getItem('user_email');

    if (!email) {
      return;
    }

    this.authService.checkStatus(email).subscribe({
      next: (res: any) => {
        console.log('Account status check:', res);

        if (!res.is_active) {
          alert('❌ Akun Anda telah diblokir oleh admin. Anda akan logout.');

          localStorage.clear();
          this.navCtrl.navigateRoot('/login');
        }
      },
      error: (err: any) => {
        console.log('Status check error:', err);

        if (err.status === 403 || err.status === 401) {
          localStorage.clear();
          this.navCtrl.navigateRoot('/login');
        }
      }
    });
  }

  private startStatusCheckInterval() {
    this.stopStatusCheckInterval();

    this.statusCheckInterval = setInterval(() => {
      this.checkAccountStatus();
    }, 10000);
  }

  private stopStatusCheckInterval() {
    if (this.statusCheckInterval) {
      clearInterval(this.statusCheckInterval);
      this.statusCheckInterval = null;
    }
  }

  private updateOperatorActivity() {
    const email = localStorage.getItem('user_email');

    if (!email) {
      return;
    }

    this.authService.updateActivity(email).subscribe({
      next: (res: any) => {
        console.log('Activity updated:', res);
      },
      error: (err: any) => {
        console.log('Activity update error:', err);

        if (err.status === 403) {
          alert('❌ Akun Anda telah diblokir oleh admin.');

          localStorage.clear();
          this.navCtrl.navigateRoot('/login');
        }
      }
    });
  }

  private startActivityInterval() {
    this.stopActivityInterval();

    this.activityInterval = setInterval(() => {
      this.updateOperatorActivity();
    }, 30000);
  }

  private stopActivityInterval() {
    if (this.activityInterval) {
      clearInterval(this.activityInterval);
      this.activityInterval = null;
    }
  }

  private loadInitialData() {
    this.loadNotificationCount();
    this.loadNotifications();
    this.loadBarang();
  }

  private startNotificationPolling() {
    this.stopNotificationPolling();

    this.notifInterval = setInterval(() => {
      this.loadNotificationCount();

      if (this.showNotification) {
        this.loadNotifications();
      }
    }, 5000);
  }

  private stopNotificationPolling() {
    if (this.notifInterval) {
      clearInterval(this.notifInterval);
      this.notifInterval = null;
    }
  }

  async initPushNotification() {
    if (this.pushInitialized) {
      return;
    }

    this.pushInitialized = true;

    if (!Capacitor.isNativePlatform()) {
      console.log('Push notification dilewati karena bukan Android/iOS.');
      return;
    }

    const localPermission =
      await LocalNotifications.requestPermissions();

    console.log(
      'Local notification permission:',
      localPermission
    );

    let pushPermission =
      await PushNotifications.checkPermissions();

    if (pushPermission.receive !== 'granted') {
      pushPermission =
        await PushNotifications.requestPermissions();
    }

    if (pushPermission.receive !== 'granted') {
      console.log('Izin push notification ditolak user.');
      return;
    }

    await PushNotifications.register();

    PushNotifications.addListener(
      'registration',
      (token) => {
        console.log('FCM TOKEN:', token.value);

        const userData = localStorage.getItem('user');
        const user = userData ? JSON.parse(userData) : null;

        this.notificationService.saveFcmToken({
          token: token.value,
          user_id: user?.id || null,
          platform: Capacitor.getPlatform()
        }).subscribe({
          next: (res) => {
            console.log('FCM token berhasil disimpan:', res);
          },
          error: (err) => {
            console.log('Gagal simpan FCM token:', err);
          }
        });
      }
    );

    PushNotifications.addListener(
      'registrationError',
      (error) => {
        console.log('Push registration error:', error);
      }
    );

    PushNotifications.addListener(
      'pushNotificationReceived',
      async (notification) => {
        console.log('NOTIF MASUK:', notification);

        this.loadNotificationCount();
        this.loadNotifications();

        await LocalNotifications.schedule({
          notifications: [
            {
              title: notification.title || 'Logista',
              body: notification.body || 'Ada notifikasi baru',
              id: Math.floor(Date.now() / 1000),
              schedule: {
                at: new Date(Date.now() + 1000),
              },
            },
          ],
        });
      }
    );

    PushNotifications.addListener(
      'pushNotificationActionPerformed',
      () => {
        this.navCtrl.navigateForward('/barang-masuk');
      }
    );
  }

  loadBarang() {
    this.barangService.getBarang().subscribe({
      next: (res: any) => {
        this.allBarang = res?.data || [];
      },
      error: (err) => {
        console.log('Gagal load barang:', err);
      },
    });
  }

  filterBarang(event: any) {
    const keyword =
      event?.target?.value?.toLowerCase()?.trim();

    if (!keyword) {
      this.searchResults = [];
      return;
    }

    this.searchResults =
      this.allBarang.filter((item: any) => {
        const namaBarang =
          item?.nama_barang?.toLowerCase() || '';

        const kodeBarang =
          item?.kode_barang?.toLowerCase() || '';

        return (
          namaBarang.includes(keyword) ||
          kodeBarang.includes(keyword)
        );
      });
  }

  loadNotificationCount() {
    this.notificationService
      .getNotificationCount()
      .subscribe({
        next: (res: any) => {
          this.notificationCount = res?.total || 0;
        },
        error: (err) => {
          console.log('Gagal load notification count:', err);
        },
      });
  }

  loadNotifications() {
    this.notificationService
      .getNotifications()
      .subscribe({
        next: (res: any) => {
          this.notifications = res?.data || [];
        },
        error: (err) => {
          console.log('Gagal load notifications:', err);
        },
      });
  }

  toggleNotification() {
    this.showNotification =
      !this.showNotification;

    if (this.showNotification) {
      this.loadNotifications();
      this.loadNotificationCount();
    }
  }

  openBarangMasuk() {
    this.showNotification = false;

    this.navCtrl.navigateForward(
      '/barang-masuk'
    );
  }

 logout() {
  const email = localStorage.getItem('user_email');

  // Matikan semua interval dulu supaya updateActivity tidak jalan lagi
  this.stopNotificationPolling();
  this.stopActivityInterval();
  this.stopStatusCheckInterval();

  if (!email) {
    localStorage.clear();

    this.navCtrl.navigateRoot(
      '/login'
    );

    return;
  }

  this.authService.logout(email).subscribe({
    next: (res: any) => {
      console.log('Logout berhasil:', res);

      localStorage.clear();

      this.navCtrl.navigateRoot(
        '/login'
      );
    },
    error: (err: any) => {
      console.log('Logout error:', err);

      // Tetap logout dari aplikasi walaupun request backend error
      localStorage.clear();

      this.navCtrl.navigateRoot(
        '/login'
      );
    }
  });
}
  goToBarang() {
    this.navCtrl.navigateForward(
      '/daftar-barang'
    );
  }

  goToStok() {
    this.navCtrl.navigateForward(
      '/stok-barang'
    );
  }

  goToBarangMasuk() {
    this.navCtrl.navigateForward(
      '/barang-masuk'
    );
  }

  goTomutasiBarang() {
    this.navCtrl.navigateForward(
      '/mutasi-barang'
    );
  }

  goToHistori() {
    this.navCtrl.navigateForward(
      '/histori'
    );
  }

  goToUpdateStok() {
    this.navCtrl.navigateForward(
      '/update-stok'
    );
  }

  goToBarangKeluar() {
    this.navCtrl.navigateForward(
      '/barang-keluar'
    );
  }
}
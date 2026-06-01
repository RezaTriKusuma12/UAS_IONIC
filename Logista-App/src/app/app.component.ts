import { Component } from '@angular/core';

import { Router } from '@angular/router';

import { Platform } from '@ionic/angular';

import { Location } from '@angular/common';

import { App } from '@capacitor/app';

@Component({

  selector: 'app-root',

  templateUrl: 'app.component.html',

  styleUrls: ['app.component.scss'],

  standalone: false,

})

export class AppComponent {

  constructor(

    private router:
    Router,

    private platform:
    Platform,

    private location:
    Location

  ) {

    this.initializeApp();

  }

  // =====================================
  // INIT APP
  // =====================================

  initializeApp() {

    this.platform.ready()
    .then(() => {

      // =========================
      // HANDLE BACK BUTTON ANDROID
      // =========================

      this.handleBackButton();

      // =========================
      // MASUK KE SPLASH
      // =========================

      this.router.navigate(
        ['/splash'],
        {
          replaceUrl: true
        }
      );

    });

  }

  // =====================================
  // BACK BUTTON ANDROID
  // =====================================

  handleBackButton() {

    this.platform.backButton
    .subscribeWithPriority(
      9999,
      () => {

        const currentUrl =
          this.router.url.split('?')[0];

        // =========================
        // JIKA DI HOME ATAU LOGIN
        // KELUAR APLIKASI
        // =========================

        if (
          currentUrl === '/home' ||
          currentUrl === '/login'
        ) {

          App.exitApp();

        }

        // =========================
        // JIKA DI HALAMAN LAIN
        // KEMBALI KE HALAMAN SEBELUMNYA
        // =========================

        else {

          this.location.back();

        }

      }
    );

  }

  // =====================================
  // LOGOUT
  // =====================================

  logout() {

    localStorage.removeItem('user');
    localStorage.removeItem('token');

    this.router.navigate(
      ['/login'],
      {
        replaceUrl: true
      }
    );

  }

  // =====================================
  // GO HOME
  // =====================================

  goHome() {

    this.router.navigateByUrl(
      '/home'
    );

  }

}
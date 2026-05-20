import { Component }
from '@angular/core';

import { Router }
from '@angular/router';

import { Platform }
from '@ionic/angular';

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
    Platform

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
      // CEK WELCOME PAGE
      // =========================

      const welcomeShown =

        localStorage.getItem(
          'welcomeShown'
        );

      // =========================
      // CEK LOGIN
      // =========================

      const user =

        localStorage.getItem(
          'user'
        );

      // =========================
      // JIKA BELUM PERNAH
      // MASUK APP
      // =========================

      if (!welcomeShown) {

        this.router.navigate(
          ['/welcome'],
          {
            replaceUrl: true
          }
        );

        return;

      }

      // =========================
      // JIKA SUDAH LOGIN
      // =========================

      if (user) {

        this.router.navigate(
          ['/splash'],
          {
            replaceUrl: true
          }
        );

      }

      // =========================
      // JIKA BELUM LOGIN
      // =========================

      else {

        this.router.navigate(
          ['/splash'],
          {
            replaceUrl: true
          }
        );

      }

    });

  }

  // =====================================
  // LOGOUT
  // =====================================

  logout() {

    localStorage.clear();

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
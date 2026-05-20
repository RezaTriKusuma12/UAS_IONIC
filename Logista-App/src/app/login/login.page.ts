import {
  Component,
  OnInit,
  OnDestroy
} from '@angular/core';

import { Router } from '@angular/router';

import {
  Platform
} from '@ionic/angular';

import { App }
from '@capacitor/app';

import { AuthService }
from '../services/auth';

@Component({
  selector: 'app-login',
  templateUrl: './login.page.html',
  styleUrls: ['./login.page.scss'],
  standalone: false,
})

export class LoginPage
implements OnInit, OnDestroy {

  email: string = '';

  password: string = '';

  backButtonSubscription: any;

  constructor(

    private router: Router,

    private authService:
    AuthService,

    private platform: Platform

  ) {}

  // =====================================
  // INIT
  // =====================================

  ngOnInit() {

    // jika sudah login
    // langsung ke home

    const user =
      localStorage.getItem('user');

    if (user) {

      this.router.navigate(
        ['/home']
      );

    }

    // =====================================
    // BACK BUTTON ANDROID
    // =====================================

    this.backButtonSubscription =

      this.platform.backButton
      .subscribeWithPriority(
        9999,
        () => {

          App.exitApp();

        }
      );

  }

  // =====================================
  // DESTROY
  // =====================================

  ngOnDestroy() {

    if (
      this.backButtonSubscription
    ) {

      this.backButtonSubscription
      .unsubscribe();

    }

  }

  // =====================================
  // LOGIN
  // =====================================

  login() {

    if (
      !this.email ||
      !this.password
    ) {

      alert(
        'Isi semua field'
      );

      return;

    }

    this.authService.login({

      email: this.email,

      password: this.password

    })

    .subscribe({

      next: (res: any) => {

        console.log(res);

        alert(res.message);

        // simpan user

        localStorage.setItem(
          'user',
          JSON.stringify(
            res.user
          )
        );

        // pindah home

        this.router.navigate(
          ['/home']
        );

      },

      error: (err: any) => {

        console.log(err);

        alert(

          err.error?.message ||

          'Login gagal'

        );

      }

    });

  }

  // =====================================
  // NAVIGATION
  // =====================================

  goToForgotPassword() {

    this.router.navigate([
      '/lupa-password'
    ]);

  }

  goToRegister() {

    this.router.navigate([
      '/register'
    ]);

  }

}
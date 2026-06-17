import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../services/auth';

import {
  eyeOutline,
  eyeOffOutline
} from 'ionicons/icons';

@Component({
  selector: 'app-login',
  templateUrl: './login.page.html',
  styleUrls: ['./login.page.scss'],
  standalone: false,
})

export class LoginPage implements OnInit {

  email: string = '';
  password: string = '';

  showPassword: boolean = false;

  eyeIcon = eyeOutline;
  eyeOffIcon = eyeOffOutline;

  constructor(
    private router: Router,
    private authService: AuthService
  ) {}

  ngOnInit() {

    localStorage.setItem(
      'welcomeShown',
      'true'
    );

    const user =
      localStorage.getItem('user');

    if (user) {

      this.router.navigate(
        ['/home'],
        {
          replaceUrl: true
        }
      );

    }

  }

  // =====================================
  // SHOW / HIDE PASSWORD
  // =====================================

  togglePassword() {

    this.showPassword =
      !this.showPassword;

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

        if (res.success === false) {

          alert(
            res.message || 'Login gagal'
          );

          return;

        }

        if (!res.user) {

          alert(
            res.message || 'Data user tidak ditemukan'
          );

          return;

        }

        localStorage.setItem(
          'welcomeShown',
          'true'
        );

        localStorage.setItem(
          'user',
          JSON.stringify(
            res.user
          )
        );

        if (res.user?.email) {

          localStorage.setItem(
            'user_email',
            res.user.email
          );

        }

        alert(
          res.message || 'Login berhasil'
        );

        this.router.navigate(
          ['/home'],
          {
            replaceUrl: true
          }
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
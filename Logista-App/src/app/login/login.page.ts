import {
  Component,
  OnInit
} from '@angular/core';

import { Router } from '@angular/router';

import { AuthService }
from '../services/auth';

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

export class LoginPage
implements OnInit {

  email: string = '';

  password: string = '';

  showPassword: boolean = false;

  eyeIcon = eyeOutline;

  eyeOffIcon = eyeOffOutline;

  constructor(

    private router: Router,

    private authService:
    AuthService

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

        alert(res.message);

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
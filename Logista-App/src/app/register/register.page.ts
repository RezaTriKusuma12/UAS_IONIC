import { Component, OnInit } from '@angular/core';
import { AuthService } from '../services/auth';
import { Router } from '@angular/router';

@Component({
  selector: 'app-register',
  templateUrl: './register.page.html',
  styleUrls: ['./register.page.scss'],
  standalone: false,
})
export class RegisterPage implements OnInit {

  name: string = '';
  email: string = '';
  username: string = '';
  password: string = '';

  constructor(
    private router: Router,
    private authService: AuthService
  ) {}

  ngOnInit() {}

  register() {
    if (!this.name || !this.email || !this.username || !this.password) {
      alert('Semua field wajib diisi!');
      return;
    }

    this.authService.register({
      name: this.name,
      email: this.email,
      username: this.username,
      password: this.password
    }).subscribe({
      next: (res) => {
        console.log(res);
        alert('Register berhasil');
      },
      error: (err) => {
        console.log(err);
        alert('Register gagal');
      }
    });
  }

   goToLogin() {
    this.router.navigate(['/login']);
  }
}
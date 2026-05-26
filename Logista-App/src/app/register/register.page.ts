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
  const data = {
    email: this.email,
    name: this.name,
    username: this.username,
    password: this.password
  };

  this.authService.register(data).subscribe({
    next: (res: any) => {
      console.log(res);

      alert('Registrasi berhasil, silakan login');

      this.router.navigate(['/login']);
    },
    error: (err) => {
      console.log(err);

      alert(
        err?.error?.message ||
        'Registrasi gagal'
      );
    }
  });
}

   goToLogin() {
    this.router.navigate(['/login']);
  }
}
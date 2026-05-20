import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../services/auth';

@Component({
  selector: 'app-lupa-password',
  templateUrl: './lupa-password.page.html',
  styleUrls: ['./lupa-password.page.scss'],
  standalone : false
})
export class LupaPasswordPage implements OnInit {

  email: string = '';

  constructor(
    private router: Router,
    private auth: AuthService
  ) {}

  ngOnInit() {}

  sendOtp() {
    if (!this.email) {
      alert('Masukkan email dulu');
      return;
    }

    this.auth.sendOtp(this.email).subscribe({
      next: () => {
        alert('OTP dikirim ke email');
        this.router.navigate(['/masukkan-otp'], {
          queryParams: { email: this.email }
        });
      },
      error: () => {
        alert('Email tidak ditemukan');
      }
    });
  }
}
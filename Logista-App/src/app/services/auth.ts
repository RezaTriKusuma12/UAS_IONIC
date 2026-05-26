import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { environment } from 'src/environments/environment';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  // backend berjalan di port 3000, sesuaikan di sini
  apiUrl = environment.apiUrl;// ganti IP kamu jika memakai device

  constructor(private http: HttpClient) {}

  register(data: any) {
    return this.http.post(`${this.apiUrl}/register`, data);
  }

  login(data: any) {
    return this.http.post(`${this.apiUrl}/login`, data);
  }

  // 🔐 OTP
  sendOtp(email: string) {
    return this.http.post(`${this.apiUrl}/lupa-password`, { email });
  }

  verifyOtp(email: string, otp: string) {
    return this.http.post(`${this.apiUrl}/masukkan-otp`, { email, otp });
  }

  resetPassword(email: string, password: string) {
    return this.http.post(`${this.apiUrl}/reset-password`, { email, password });
  }

}
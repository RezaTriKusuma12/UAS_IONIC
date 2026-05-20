import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  // ⚠️ GANTI kalau pakai HP (pakai IP, bukan localhost)
  apiUrl = 'http://localhost:3000'; // ganti IP kamu

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
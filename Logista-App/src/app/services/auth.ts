import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { environment } from 'src/environments/environment';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  apiUrl = environment.apiUrl;

  constructor(private http: HttpClient) {}

  register(data: any): Observable<any> {
    return this.http.post(`${this.apiUrl}/register`, data);
  }

  login(data: any): Observable<any> {
    return this.http.post(`${this.apiUrl}/login-operator`, data);
  }

  sendOtp(email: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/lupa-password`, { email });
  }

  verifyOtp(email: string, otp: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/masukkan-otp`, { email, otp });
  }

  resetPassword(email: string, password: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/reset-password`, {
      email,
      password
    });
  }

  updateActivity(email: string): Observable<any> {
    return this.http.put(`${this.apiUrl}/update-activity`, {
      email
    });
  }

  checkStatus(email: string): Observable<any> {
    return this.http.get(
      `${this.apiUrl}/check-status?email=${encodeURIComponent(email)}`
    );
  }

  logout(email: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/logout-operator`, {
      email
    });
  }
}
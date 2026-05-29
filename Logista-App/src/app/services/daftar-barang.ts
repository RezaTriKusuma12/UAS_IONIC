import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable({
  providedIn: 'root'
})
export class BarangService {

  apiUrl = 'https://luminous.my.id/api'; // GANTI IP KAMU

  constructor(private http: HttpClient) {}

  getBarang() {
    return this.http.get(`${this.apiUrl}/barang`);
  }
}
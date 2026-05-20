import { Injectable } from '@angular/core';

import { HttpClient } from '@angular/common/http';

@Injectable({
  providedIn: 'root'
})

export class BarangKeluarService {

  apiUrl = 'http://localhost:3000/api';

  constructor(
    private http: HttpClient
  ) {}

  // =========================
  // GET BARANG
  // =========================

  getBarang() {

    return this.http.get(
      `${this.apiUrl}/barang`
    );

  }

  // =========================
  // BARANG KELUAR
  // =========================

  barangKeluar(data: any) {

    return this.http.post(
      `${this.apiUrl}/barang-keluar`,
      data
    );

  }

}
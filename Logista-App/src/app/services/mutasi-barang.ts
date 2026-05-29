import { Injectable } from '@angular/core';

import { HttpClient }
from '@angular/common/http';

@Injectable({
  providedIn: 'root'
})

export class MutasiBarangService {

  apiUrl =
    'https://luminous.my.id/api';

  constructor(private http: HttpClient ) {}

  // =========================
  // GET BARANG
  // =========================

  getBarang() {

    return this.http.get(
      `${this.apiUrl}/barang`
    );

  }

  // =========================
  // MUTASI BARANG
  // =========================

  mutasiBarang(data: any) {

    return this.http.post(

      `${this.apiUrl}/mutasi-barang`,

      data

    );

  }

}
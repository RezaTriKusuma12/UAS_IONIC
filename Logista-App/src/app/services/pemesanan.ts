import { Injectable } from '@angular/core';

import { HttpClient }
from '@angular/common/http';

@Injectable({
  providedIn: 'root'
})

export class PemesananService {

  apiUrl =
    'http://localhost:3000/api';

  constructor(
    private http: HttpClient
  ) {}

  // =====================================
  // AMBIL PEMESANAN
  // =====================================

  getPemesanan() {

    return this.http.get(
      `${this.apiUrl}/pemesanan`
    );

  }

  // =====================================
  // TAMBAH PEMESANAN
  // =====================================

  tambahPemesanan(data: any) {

    return this.http.post(

      `${this.apiUrl}/pemesanan`,

      data

    );

  }

  // =====================================
  // VERIFIKASI BARANG
  // =====================================

  verifikasiBarang(data: any) {

    return this.http.post(

      `${this.apiUrl}/verifikasi-barang`,

      data

    );

  }

}
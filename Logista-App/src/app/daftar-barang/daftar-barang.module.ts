import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { IonicModule } from '@ionic/angular';

import { DaftarBarangPage } from './daftar-barang.page';
import { DaftarBarangPageRoutingModule } from './daftar-barang-routing.module';

import { HttpClientModule } from '@angular/common/http'; // ✅ TAMBAHKAN

@NgModule({
  imports: [
    CommonModule,
    FormsModule,
    IonicModule,
    HttpClientModule, // ✅ WAJIB
    DaftarBarangPageRoutingModule
  ],
  declarations: [DaftarBarangPage]
})
export class DaftarBarangPageModule {}
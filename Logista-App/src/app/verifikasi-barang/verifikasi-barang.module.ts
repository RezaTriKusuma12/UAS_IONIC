import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { IonicModule } from '@ionic/angular';

import { VerifikasiBarangPageRoutingModule } from './verifikasi-barang-routing.module';

import { VerifikasiBarangPage } from './verifikasi-barang.page';

@NgModule({
  imports: [
    CommonModule,
    FormsModule,
    IonicModule,
    VerifikasiBarangPageRoutingModule
  ],
  declarations: [VerifikasiBarangPage]
})
export class VerifikasiBarangPageModule {}

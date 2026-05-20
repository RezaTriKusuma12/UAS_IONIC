import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { IonicModule } from '@ionic/angular';

import { MutasiBarangPageRoutingModule } from './mutasi-barang-routing.module';

import { MutasiBarangPage } from './mutasi-barang.page';

@NgModule({
  imports: [
    CommonModule,
    FormsModule,
    IonicModule,
    MutasiBarangPageRoutingModule
  ],
  declarations: [MutasiBarangPage]
})
export class MutasiBarangPageModule {}

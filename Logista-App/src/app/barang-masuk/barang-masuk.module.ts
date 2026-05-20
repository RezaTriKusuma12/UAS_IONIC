import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { IonicModule } from '@ionic/angular';

import { BarangMasukPageRoutingModule } from './barang-masuk-routing.module';

import { BarangMasukPage } from './barang-masuk.page';

@NgModule({
  imports: [
    CommonModule,
    FormsModule,
    IonicModule,
    BarangMasukPageRoutingModule
  ],
  declarations: [BarangMasukPage]
})
export class BarangMasukPageModule {}

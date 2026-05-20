import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { IonicModule } from '@ionic/angular';

import { StokBarangPageRoutingModule } from './stok-barang-routing.module';

import { StokBarangPage } from './stok-barang.page';

@NgModule({
  imports: [
    CommonModule,
    FormsModule,
    IonicModule,
    StokBarangPageRoutingModule
  ],
  declarations: [StokBarangPage]
})
export class StokBarangPageModule {}

import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { IonicModule } from '@ionic/angular';

import { FormBarangKeluarPageRoutingModule } from './form-barang-keluar-routing.module';

import { FormBarangKeluarPage } from './form-barang-keluar.page';

@NgModule({
  imports: [
    CommonModule,
    FormsModule,
    IonicModule,
    FormBarangKeluarPageRoutingModule
  ],
  declarations: [FormBarangKeluarPage]
})
export class FormBarangKeluarPageModule {}

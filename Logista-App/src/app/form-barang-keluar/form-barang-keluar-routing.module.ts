import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

import { FormBarangKeluarPage } from './form-barang-keluar.page';

const routes: Routes = [
  {
    path: '',
    component: FormBarangKeluarPage
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule],
})
export class FormBarangKeluarPageRoutingModule {}

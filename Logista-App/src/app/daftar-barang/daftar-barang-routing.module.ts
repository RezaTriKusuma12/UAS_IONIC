import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

import { DaftarBarangPage } from './daftar-barang.page';

const routes: Routes = [
  {
    path: '',
    component: DaftarBarangPage
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule],
})
export class DaftarBarangPageRoutingModule {}

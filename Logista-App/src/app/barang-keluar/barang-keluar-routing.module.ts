import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

import { BarangKeluarPage } from './barang-keluar.page';

const routes: Routes = [
  {
    path: '',
    component: BarangKeluarPage
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule],
})
export class BarangKeluarPageRoutingModule {}

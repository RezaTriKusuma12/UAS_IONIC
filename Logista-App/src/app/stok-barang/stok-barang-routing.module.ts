import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

import { StokBarangPage } from './stok-barang.page';

const routes: Routes = [
  {
    path: '',
    component: StokBarangPage
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule],
})
export class StokBarangPageRoutingModule {}

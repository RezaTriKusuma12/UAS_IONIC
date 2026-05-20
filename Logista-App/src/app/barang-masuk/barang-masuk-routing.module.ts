import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

import { BarangMasukPage } from './barang-masuk.page';

const routes: Routes = [
  {
    path: '',
    component: BarangMasukPage
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule],
})
export class BarangMasukPageRoutingModule {}

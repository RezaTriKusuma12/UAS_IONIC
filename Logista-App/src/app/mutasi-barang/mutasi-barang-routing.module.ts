import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

import { MutasiBarangPage } from './mutasi-barang.page';

const routes: Routes = [
  {
    path: '',
    component: MutasiBarangPage
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule],
})
export class MutasiBarangPageRoutingModule {}

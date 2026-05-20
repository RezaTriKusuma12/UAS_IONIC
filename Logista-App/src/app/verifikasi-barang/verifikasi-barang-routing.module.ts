import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

import { VerifikasiBarangPage } from './verifikasi-barang.page';

const routes: Routes = [
  {
    path: '',
    component: VerifikasiBarangPage
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule],
})
export class VerifikasiBarangPageRoutingModule {}

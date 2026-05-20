import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

import { UpdateStokPage } from './update-stok.page';

const routes: Routes = [
  {
    path: '',
    component: UpdateStokPage
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule],
})
export class UpdateStokPageRoutingModule {}

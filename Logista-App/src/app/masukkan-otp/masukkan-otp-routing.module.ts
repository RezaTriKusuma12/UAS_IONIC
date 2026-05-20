import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

import { MasukkanOTPPage } from './masukkan-otp.page';

const routes: Routes = [
  {
    path: '',
    component: MasukkanOTPPage
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule],
})
export class MasukkanOTPPageRoutingModule {}

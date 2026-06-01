import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

import { PrivacyPolicePage } from './privacy-police.page';

const routes: Routes = [
  {
    path: '',
    component: PrivacyPolicePage
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule],
})
export class PrivacyPolicePageRoutingModule {}

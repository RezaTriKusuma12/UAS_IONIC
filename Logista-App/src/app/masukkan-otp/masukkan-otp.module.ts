import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { IonicModule } from '@ionic/angular';

import { MasukkanOTPPageRoutingModule } from './masukkan-otp-routing.module';

import { MasukkanOTPPage } from './masukkan-otp.page';

@NgModule({
  imports: [
    CommonModule,
    FormsModule,
    IonicModule,
    MasukkanOTPPageRoutingModule
  ],
  declarations: [MasukkanOTPPage]
})
export class MasukkanOTPPageModule {}

import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { IonicModule } from '@ionic/angular';

import { UpdateStokPageRoutingModule } from './update-stok-routing.module';

import { UpdateStokPage } from './update-stok.page';

@NgModule({
  imports: [
    CommonModule,
    FormsModule,
    IonicModule,
    UpdateStokPageRoutingModule
  ],
  declarations: [UpdateStokPage]
})
export class UpdateStokPageModule {}

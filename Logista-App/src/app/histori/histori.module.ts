import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { IonicModule } from '@ionic/angular';

import { HistoriPageRoutingModule } from './histori-routing.module';

import { HistoriPage } from './histori.page';

@NgModule({
  imports: [
    CommonModule,
    FormsModule,
    IonicModule,
    HistoriPageRoutingModule
  ],
  declarations: [HistoriPage]
})
export class HistoriPageModule {}

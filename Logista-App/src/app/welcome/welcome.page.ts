import { Component }
from '@angular/core';

import { NavController }
from '@ionic/angular';

@Component({

  selector: 'app-welcome',

  templateUrl: './welcome.page.html',

  styleUrls: ['./welcome.page.scss'],

  standalone: false

})

export class WelcomePage {

  isAgree: boolean = false;

  constructor(

    private navCtrl:
    NavController

  ) {}

  startApp() {

    // wajib checklist
    if (!this.isAgree) {

      alert(
        'Silakan setujui Terms terlebih dahulu'
      );

      return;

    }

    // tandai sudah buka app
    localStorage.setItem(
      'welcomeShown',
      'true'
    );

    // masuk login
    this.navCtrl.navigateRoot(
      '/login'
    );

  }

}
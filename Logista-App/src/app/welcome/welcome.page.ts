import { Component } from '@angular/core';

import { Router } from '@angular/router';

@Component({

  selector: 'app-welcome',

  templateUrl: './welcome.page.html',

  styleUrls: ['./welcome.page.scss'],

  standalone: false,

})

export class WelcomePage {

  isAgree: boolean = false;

  constructor(
    private router: Router
  ) {}

  mulai() {

    if (!this.isAgree) {

      return;

    }

    localStorage.setItem(
      'welcomeShown',
      'true'
    );

    this.router.navigate(
      ['/splash'],
      {
        replaceUrl: true
      }
    );

  }

  bukaPrivacyPolicy() {

    this.router.navigate(
      ['/privacy-policy']
    );

  }

}

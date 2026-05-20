import {
  Component,
  OnInit
} from '@angular/core';

import {
  NavController
} from '@ionic/angular';

@Component({
  selector: 'app-splash',
  templateUrl: './splash.page.html',
  styleUrls: ['./splash.page.scss'],
  standalone: false
})

export class SplashPage
implements OnInit {

  constructor(

    private navCtrl:
    NavController

  ) {}

  ngOnInit() {

    setTimeout(() => {

      // cek login
      const user =
        localStorage.getItem(
          'user'
        );

      // jika sudah login
      if (user) {

        this.navCtrl
        .navigateRoot(
          '/home'
        );

      }

      // jika belum login
      else {

        this.navCtrl
        .navigateRoot(
          '/login'
        );

      }

    }, 2500);

  }

}
import { Injectable } from '@angular/core';

import {
  CanActivate,
  Router,
  UrlTree
} from '@angular/router';

@Injectable({
  providedIn: 'root'
})

export class IntroGuard implements CanActivate {

  constructor(
    private router: Router
  ) {}

  canActivate(): boolean | UrlTree {

    const welcomeShown =
      localStorage.getItem('welcomeShown');

    if (welcomeShown === 'true') {

      return true;

    }

    return this.router.parseUrl('/welcome');

  }

}
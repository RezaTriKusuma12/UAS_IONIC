import {
  Component,
  OnInit,
  OnDestroy,
  ViewChild
} from '@angular/core';

import {
  Router,
  ActivatedRoute
} from '@angular/router';

import {
  IonInput
} from '@ionic/angular';

import {
  AuthService
} from '../services/auth';

@Component({
  selector: 'app-masukkan-otp',
  templateUrl: './masukkan-otp.page.html',
  styleUrls: ['./masukkan-otp.page.scss'],
  standalone: false,
})

export class MasukkanOTPPage
implements OnInit, OnDestroy {

  email: string = '';

  otpTimer: any;

  constructor(
    private router: Router,
    private route: ActivatedRoute,
    private auth: AuthService
  ) {}

  // =====================================
  // INIT
  // =====================================

  ngOnInit() {

    this.email =
      this.route.snapshot
      .queryParams['email'];

  }

  // =====================================
  // DESTROY
  // =====================================

  ngOnDestroy() {

    if (this.otpTimer) {

      clearInterval(this.otpTimer);

    }

  }

  @ViewChild('otp1') otp1!: IonInput;

  @ViewChild('otp2') otp2!: IonInput;

  @ViewChild('otp3') otp3!: IonInput;

  @ViewChild('otp4') otp4!: IonInput;

  // =====================================
  // MOVE OTP INPUT
  // =====================================

  moveNext(event: any, index: number) {

    const value =
      event.detail.value;

    if (!value) return;

    setTimeout(() => {

      if (index === 1)
        this.otp2.setFocus();

      if (index === 2)
        this.otp3.setFocus();

      if (index === 3)
        this.otp4.setFocus();

    }, 100);

  }

  // =====================================
  // VERIFY OTP
  // =====================================

  verifyOtp() {

    Promise.all([

      this.otp1.getInputElement(),

      this.otp2.getInputElement(),

      this.otp3.getInputElement(),

      this.otp4.getInputElement()

    ]).then(inputs => {

      const otp =
        inputs.map(i => i.value)
        .join('');

      if (otp.length < 4) {

        alert('OTP belum lengkap');

        return;

      }

      this.auth
      .verifyOtp(this.email, otp)

      .subscribe({

        next: () => {

          alert('OTP benar');

          this.router.navigate(
            ['/reset-password'],
            {
              queryParams: {
                email: this.email
              }
            }
          );

        },

        error: () => {

          alert(
            'OTP salah atau expired'
          );

        }

      });

    });

  }

}
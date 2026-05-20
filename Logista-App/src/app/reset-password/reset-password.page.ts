import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from '../services/auth';

@Component({
  selector: 'app-reset-password',
  templateUrl: './reset-password.page.html',
  styleUrls: ['./reset-password.page.scss'],
  standalone : false,
})
export class ResetPasswordPage implements OnInit {

  email: string = '';
  newPassword: string = '';
  confirmPassword: string = '';

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private auth: AuthService
  ) {}

  ngOnInit() {
    this.email = this.route.snapshot.queryParams['email'];
  }

  resetPassword() {

  if (this.newPassword !== this.confirmPassword) {
    alert('Password tidak sama');
    return;
  }

  this.auth.resetPassword(this.email, this.newPassword).subscribe({
    next: () => {
      alert('Password berhasil diubah');

      // ✅ LANGSUNG KE LOGIN
      this.router.navigate(['/login']);
    },
    error: () => {
      alert('Gagal reset password');
    }
  });
}
}
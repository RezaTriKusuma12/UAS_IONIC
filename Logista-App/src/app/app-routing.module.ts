import { NgModule } from '@angular/core';
import { PreloadAllModules, RouterModule, Routes } from '@angular/router';
import { WelcomeGuard } from './guards/welcome.guard';
import { IntroGuard } from './guards/intro-guard';

const routes: Routes = [
  {
    path: '',
    redirectTo: 'splash',
    pathMatch: 'full'
  },
  {
    path: 'login',
    loadChildren: () => import('./login/login.module').then( m => m.LoginPageModule)
  },
  {
    path: 'home',
    loadChildren: () => import('./home/home.module').then( m => m.HomePageModule),
    canActivate: [IntroGuard]
  },
  {
    path: 'register',
    loadChildren: () => import('./register/register.module').then( m => m.RegisterPageModule),
    canActivate: [IntroGuard]
  },
  {
    path: 'lupa-password',
    loadChildren: () => import('./lupa-password/lupa-password.module').then( m => m.LupaPasswordPageModule),
    canActivate: [IntroGuard]
  },
  {
    path: 'masukkan-otp',
    loadChildren: () => import('./masukkan-otp/masukkan-otp.module').then( m => m.MasukkanOTPPageModule),
    canActivate: [IntroGuard]
  },
  {
    path: 'reset-password',
    loadChildren: () => import('./reset-password/reset-password.module').then( m => m.ResetPasswordPageModule),
    canActivate: [IntroGuard]
  },

  // --- HALAMAN OPERASIONAL (SESUAI STRUKTUR FOLDER KAMU) ---
  {
    path: 'daftar-barang',
    loadChildren: () => import('./daftar-barang/daftar-barang.module').then( m => m.DaftarBarangPageModule),
    canActivate: [IntroGuard]
  },
  {
    path: 'stok-barang',
    loadChildren: () => import('./stok-barang/stok-barang.module').then( m => m.StokBarangPageModule),
    canActivate: [IntroGuard]
  },
  
  {
  path: 'mutasi-barang', 
  loadChildren: () => import('./mutasi-barang/mutasi-barang.module').then( m => m.MutasiBarangPageModule),
  canActivate: [IntroGuard]
  },
  {
    path: 'histori',
    loadChildren: () => import('./histori/histori.module').then( m => m.HistoriPageModule),
    canActivate: [IntroGuard]
  },
  {
    path: 'update-stok',
    loadChildren: () => import('./update-stok/update-stok.module').then( m => m.UpdateStokPageModule),
    canActivate: [IntroGuard]
  },
  {
    path: 'barang-masuk',
    loadChildren: () => import('./barang-masuk/barang-masuk.module').then( m => m.BarangMasukPageModule),
    canActivate: [IntroGuard]
  },
  {
    path: 'verifikasi-barang',
    loadChildren: () => import('./verifikasi-barang/verifikasi-barang.module').then( m => m.VerifikasiBarangPageModule),
    canActivate: [IntroGuard]
  },
  {
    path: 'barang-keluar',
    loadChildren: () => import('./barang-keluar/barang-keluar.module').then( m => m.BarangKeluarPageModule),
    canActivate: [IntroGuard]
  },
  {
    path: 'form-barang-keluar',
    loadChildren: () => import('./form-barang-keluar/form-barang-keluar.module').then( m => m.FormBarangKeluarPageModule),
    canActivate: [IntroGuard]
  },
  {
    path: 'splash',
    loadChildren: () => import('./splash/splash.module').then( m => m.SplashPageModule),
    canActivate: [IntroGuard]
  },
  {
    path: 'welcome',
    loadChildren: () => import('./welcome/welcome.module').then( m => m.WelcomePageModule),
    canActivate: [WelcomeGuard]
  },
  {
    path: 'privacy-police',
    loadChildren: () => import('./privacy-police/privacy-police.module').then( m => m.PrivacyPolicePageModule),
    canActivate: [IntroGuard]
  },
  
];

@NgModule({
  imports: [
    RouterModule.forRoot(routes, { preloadingStrategy: PreloadAllModules })
  ],
  exports: [RouterModule]
})
export class AppRoutingModule { }
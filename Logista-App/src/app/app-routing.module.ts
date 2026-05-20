import { NgModule } from '@angular/core';
import { PreloadAllModules, RouterModule, Routes } from '@angular/router';

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
    loadChildren: () => import('./home/home.module').then( m => m.HomePageModule)
  },
  {
    path: 'register',
    loadChildren: () => import('./register/register.module').then( m => m.RegisterPageModule)
  },
  {
    path: 'lupa-password',
    loadChildren: () => import('./lupa-password/lupa-password.module').then( m => m.LupaPasswordPageModule)
  },
  {
    path: 'masukkan-otp',
    loadChildren: () => import('./masukkan-otp/masukkan-otp.module').then( m => m.MasukkanOTPPageModule)
  },
  {
    path: 'reset-password',
    loadChildren: () => import('./reset-password/reset-password.module').then( m => m.ResetPasswordPageModule)
  },

  // --- HALAMAN OPERASIONAL (SESUAI STRUKTUR FOLDER KAMU) ---
  {
    path: 'daftar-barang',
    loadChildren: () => import('./daftar-barang/daftar-barang.module').then( m => m.DaftarBarangPageModule)
  },
  {
    path: 'stok-barang',
    loadChildren: () => import('./stok-barang/stok-barang.module').then( m => m.StokBarangPageModule)
  },
  
  {
  path: 'mutasi-barang', 
  loadChildren: () => import('./mutasi-barang/mutasi-barang.module').then( m => m.MutasiBarangPageModule)
  },
  {
    path: 'histori',
    loadChildren: () => import('./histori/histori.module').then( m => m.HistoriPageModule)
  },
  {
    path: 'update-stok',
    loadChildren: () => import('./update-stok/update-stok.module').then( m => m.UpdateStokPageModule)
  },
  {
    path: 'barang-masuk',
    loadChildren: () => import('./barang-masuk/barang-masuk.module').then( m => m.BarangMasukPageModule)
  },
  {
    path: 'verifikasi-barang',
    loadChildren: () => import('./verifikasi-barang/verifikasi-barang.module').then( m => m.VerifikasiBarangPageModule)
  },
  {
    path: 'barang-keluar',
    loadChildren: () => import('./barang-keluar/barang-keluar.module').then( m => m.BarangKeluarPageModule)
  },
  {
    path: 'form-barang-keluar',
    loadChildren: () => import('./form-barang-keluar/form-barang-keluar.module').then( m => m.FormBarangKeluarPageModule)
  },
  {
    path: 'splash',
    loadChildren: () => import('./splash/splash.module').then( m => m.SplashPageModule)
  },
  {
    path: 'welcome',
    loadChildren: () => import('./welcome/welcome.module').then( m => m.WelcomePageModule)
  },
];

@NgModule({
  imports: [
    RouterModule.forRoot(routes, { preloadingStrategy: PreloadAllModules })
  ],
  exports: [RouterModule]
})
export class AppRoutingModule { }
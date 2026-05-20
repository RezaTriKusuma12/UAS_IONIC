import { ComponentFixture, TestBed } from '@angular/core/testing';
import { VerifikasiBarangPage } from './verifikasi-barang.page';

describe('VerifikasiBarangPage', () => {
  let component: VerifikasiBarangPage;
  let fixture: ComponentFixture<VerifikasiBarangPage>;

  beforeEach(() => {
    fixture = TestBed.createComponent(VerifikasiBarangPage);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});

import { ComponentFixture, TestBed } from '@angular/core/testing';
import { DaftarBarangPage } from './daftar-barang.page';

describe('DaftarBarangPage', () => {
  let component: DaftarBarangPage;
  let fixture: ComponentFixture<DaftarBarangPage>;

  beforeEach(() => {
    fixture = TestBed.createComponent(DaftarBarangPage);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});

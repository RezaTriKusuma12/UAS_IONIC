import { ComponentFixture, TestBed } from '@angular/core/testing';
import { MutasiBarangPage } from './mutasi-barang.page';

describe('MutasiBarangPage', () => {
  let component: MutasiBarangPage;
  let fixture: ComponentFixture<MutasiBarangPage>;

  beforeEach(() => {
    fixture = TestBed.createComponent(MutasiBarangPage);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});

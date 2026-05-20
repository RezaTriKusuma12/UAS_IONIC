import { ComponentFixture, TestBed } from '@angular/core/testing';
import { StokBarangPage } from './stok-barang.page';

describe('StokBarangPage', () => {
  let component: StokBarangPage;
  let fixture: ComponentFixture<StokBarangPage>;

  beforeEach(() => {
    fixture = TestBed.createComponent(StokBarangPage);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});

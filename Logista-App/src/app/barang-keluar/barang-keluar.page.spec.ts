import { ComponentFixture, TestBed } from '@angular/core/testing';
import { BarangKeluarPage } from './barang-keluar.page';

describe('BarangKeluarPage', () => {
  let component: BarangKeluarPage;
  let fixture: ComponentFixture<BarangKeluarPage>;

  beforeEach(() => {
    fixture = TestBed.createComponent(BarangKeluarPage);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});

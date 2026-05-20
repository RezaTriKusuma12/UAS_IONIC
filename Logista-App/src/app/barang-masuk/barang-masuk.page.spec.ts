import { ComponentFixture, TestBed } from '@angular/core/testing';
import { BarangMasukPage } from './barang-masuk.page';

describe('BarangMasukPage', () => {
  let component: BarangMasukPage;
  let fixture: ComponentFixture<BarangMasukPage>;

  beforeEach(() => {
    fixture = TestBed.createComponent(BarangMasukPage);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});

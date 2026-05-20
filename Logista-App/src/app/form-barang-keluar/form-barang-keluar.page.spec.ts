import { ComponentFixture, TestBed } from '@angular/core/testing';
import { FormBarangKeluarPage } from './form-barang-keluar.page';

describe('FormBarangKeluarPage', () => {
  let component: FormBarangKeluarPage;
  let fixture: ComponentFixture<FormBarangKeluarPage>;

  beforeEach(() => {
    fixture = TestBed.createComponent(FormBarangKeluarPage);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});

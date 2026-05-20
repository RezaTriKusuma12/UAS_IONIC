import { ComponentFixture, TestBed } from '@angular/core/testing';
import { UpdateStokPage } from './update-stok.page';

describe('UpdateStokPage', () => {
  let component: UpdateStokPage;
  let fixture: ComponentFixture<UpdateStokPage>;

  beforeEach(() => {
    fixture = TestBed.createComponent(UpdateStokPage);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});

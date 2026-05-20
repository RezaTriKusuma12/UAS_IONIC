import { ComponentFixture, TestBed } from '@angular/core/testing';
import { MasukkanOTPPage } from './masukkan-otp.page';

describe('MasukkanOTPPage', () => {
  let component: MasukkanOTPPage;
  let fixture: ComponentFixture<MasukkanOTPPage>;

  beforeEach(() => {
    fixture = TestBed.createComponent(MasukkanOTPPage);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});

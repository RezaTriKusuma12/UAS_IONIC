import { ComponentFixture, TestBed } from '@angular/core/testing';
import { PrivacyPolicePage } from './privacy-police.page';

describe('PrivacyPolicePage', () => {
  let component: PrivacyPolicePage;
  let fixture: ComponentFixture<PrivacyPolicePage>;

  beforeEach(() => {
    fixture = TestBed.createComponent(PrivacyPolicePage);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});

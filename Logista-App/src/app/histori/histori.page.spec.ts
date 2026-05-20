import { ComponentFixture, TestBed } from '@angular/core/testing';
import { HistoriPage } from './histori.page';

describe('HistoriPage', () => {
  let component: HistoriPage;
  let fixture: ComponentFixture<HistoriPage>;

  beforeEach(() => {
    fixture = TestBed.createComponent(HistoriPage);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});

import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class HistoryService {

  apiUrl = 'http://localhost:3000/api';

  constructor(
    private http: HttpClient
  ) { }

  // =========================
  // GET INVENTORY HISTORY
  // =========================

  getHistory(): Observable<any> {

    return this.http.get(
      `${this.apiUrl}/inventory-history`
    );

  }

}
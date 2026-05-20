import { Injectable } from '@angular/core';

import { HttpClient } from '@angular/common/http';

@Injectable({
  providedIn: 'root'
})

export class NotificationService {

  apiUrl =
    'http://localhost:3000/api';

  constructor(
    private http: HttpClient
  ) {}

  // =====================================
  // GET NOTIFICATION COUNT
  // =====================================

  getNotificationCount() {

    return this.http.get(

      `${this.apiUrl}/notification-count`

    );

  }

  // =====================================
  // GET NOTIFICATIONS
  // =====================================

  getNotifications() {

    return this.http.get(

      `${this.apiUrl}/notification`

    );

  }

}
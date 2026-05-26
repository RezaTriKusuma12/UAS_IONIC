import { Injectable }
from '@angular/core';

import {
  HttpClient
} from '@angular/common/http';

import { Capacitor } from '@capacitor/core';

@Injectable({
  providedIn: 'root'
})

export class NotificationService {

  // =====================================
  // API URL
  // =====================================

 // Saat ionic serve di browser lokal
  private localApiUrl = 'http://localhost:8000/api';

  // Saat sudah hosting cPanel
  private productionApiUrl = 'https://domainkamu.com/api';

  apiUrl = Capacitor.isNativePlatform()
    ? this.productionApiUrl
    : this.localApiUrl;
  
    

  constructor(

    private http:
    HttpClient

  ) {}

  // =====================================
  // GET NOTIFICATIONS
  // =====================================

  getNotifications() {

    return this.http.get(

      `${this.apiUrl}/notifications`

    );

  }

  // =====================================
  // GET NOTIFICATION COUNT
  // =====================================

  getNotificationCount() {

    return this.http.get(

      `${this.apiUrl}/notifications-count`

    );

  }

  saveFcmToken(data: any) {
    return this.http.post(
      `${this.apiUrl}/save-fcm-token`,
      data
    );
  }

  // =====================================
  // READ NOTIFICATIONS
  // =====================================

  readNotifications() {

    return this.http.put(

      `${this.apiUrl}/notifications-read`,

      {}

    );

  }

}
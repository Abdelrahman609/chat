import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

const BaseUrl = 'http://localhost:3000/api/chat';
@Injectable({
  providedIn: 'root'
})
export class AuthService {

  constructor(private http: HttpClient) { }
  registerUser(body): Observable<any> {
    return this.http.post(`${BaseUrl}/register`, body);
  }
}

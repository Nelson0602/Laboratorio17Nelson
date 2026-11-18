import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';
import { AuthService } from './auth.service';

/**
 * [REMEDIACION 3.2] Adjunta el JWT en la cabecera Authorization de cada peticion a la API.
 * El backend deriva la identidad del usuario exclusivamente de este token.
 * Ante un 401 (token ausente/expirado) se cierra la sesion local.
 */
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const auth = inject(AuthService);
  const router = inject(Router);
  const token = auth.currentUser()?.token;

  const esApi = req.url.startsWith('http://localhost:8080/api/');
  const esLogin = req.url.endsWith('/api/auth/login');
  const peticion = token && esApi && !esLogin
    ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } })
    : req;

  return next(peticion).pipe(
    catchError((err: HttpErrorResponse) => {
      if (err.status === 401 && !esLogin) {
        auth.logout();
        router.navigate(['/login']);
      }
      return throwError(() => err);
    })
  );
};

import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Cuenta, Transaccion, TransferenciaRequest } from '../models/banco.model';

@Injectable({
  providedIn: 'root'
})
export class BancoService {
  private apiUrl = 'http://localhost:8080/api';

  constructor(private http: HttpClient) {}

  obtenerCuentasUsuario(usuarioId: number): Observable<Cuenta[]> {
    return this.http.get<Cuenta[]>(`${this.apiUrl}/cuentas/usuario/${usuarioId}`);
  }

  // [REMEDIACION] El backend valida la propiedad de la cuenta (403 si es ajena)
  obtenerCuentaPorId(id: number): Observable<Cuenta> {
    return this.http.get<Cuenta>(`${this.apiUrl}/cuentas/${id}`);
  }

  listarTodasLasCuentas(): Observable<Cuenta[]> {
    return this.http.get<Cuenta[]>(`${this.apiUrl}/cuentas`);
  }

  listarTransacciones(): Observable<Transaccion[]> {
    return this.http.get<Transaccion[]>(`${this.apiUrl}/transacciones`);
  }

  obtenerTransaccionPorId(id: number): Observable<Transaccion> {
    return this.http.get<Transaccion>(`${this.apiUrl}/transacciones/${id}`);
  }

  obtenerTransaccionesPorCuenta(cuentaId: number): Observable<Transaccion[]> {
    return this.http.get<Transaccion[]>(`${this.apiUrl}/transacciones/cuenta/${cuentaId}`);
  }

  // [REMEDIACION] Busqueda atendida por JPQL parametrizado en el backend
  buscarTransacciones(termino: string): Observable<Transaccion[]> {
    return this.http.get<Transaccion[]>(`${this.apiUrl}/transacciones/buscar?termino=${encodeURIComponent(termino)}`);
  }

  // [REMEDIACION] Origen validado contra el JWT; concepto codificado como texto
  transferir(req: TransferenciaRequest): Observable<Transaccion> {
    return this.http.post<Transaccion>(`${this.apiUrl}/transacciones/transferir`, req);
  }
}


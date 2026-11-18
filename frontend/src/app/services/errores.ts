import { HttpErrorResponse } from '@angular/common/http';

/**
 * Extrae el mensaje para el usuario desde una respuesta RFC 7807 (ProblemDetail).
 * Nunca muestra trazas ni mensajes tecnicos del servidor.
 */
export function mensajeDeError(err: HttpErrorResponse, porDefecto: string): string {
  if (err.status === 0) return 'No hay conexion con el servidor.';
  const detalle = err.error?.detail;
  if (typeof detalle === 'string' && err.status < 500) return detalle;
  return porDefecto;
}

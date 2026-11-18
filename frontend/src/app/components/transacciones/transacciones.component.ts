import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { BancoService } from '../../services/banco.service';
import { AuthService } from '../../services/auth.service';
import { Transaccion } from '../../models/banco.model';
import { mensajeDeError } from '../../services/errores';

@Component({
  selector: 'app-transacciones',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule],
  templateUrl: './transacciones.component.html'
})
export class TransaccionesComponent implements OnInit {
  transacciones: Transaccion[] = [];
  txSeleccionada: Transaccion | null = null;
  terminoBusqueda = '';
  loading = false;
  errorInfo = '';

  // [REMEDIACION 3.3] Se elimino DomSanitizer.bypassSecurityTrustHtml: el concepto ya no se
  // inyecta como HTML. La plantilla usa interpolacion {{ }}, que Angular codifica siempre.
  constructor(
    private bancoService: BancoService,
    public authService: AuthService
  ) {}

  ngOnInit(): void {
    this.cargarTransacciones();
  }

  cargarTransacciones(): void {
    this.loading = true;
    this.errorInfo = '';
    this.bancoService.listarTransacciones().subscribe({
      next: (data) => {
        this.transacciones = data;
        this.loading = false;
      },
      error: (err) => {
        this.loading = false;
        this.errorInfo = mensajeDeError(err, 'No fue posible cargar el historial.');
      }
    });
  }

  // [REMEDIACION 3.1] El backend usa JPQL parametrizado; el termino se envia codificado en la URL.
  ejecutarBusqueda(): void {
    const termino = this.terminoBusqueda.trim();
    if (!termino) {
      this.cargarTransacciones();
      return;
    }
    this.loading = true;
    this.errorInfo = '';
    this.bancoService.buscarTransacciones(termino).subscribe({
      next: (data) => {
        this.transacciones = data;
        this.loading = false;
      },
      error: (err) => {
        this.loading = false;
        // [REMEDIACION 4.2] Solo se muestra el mensaje generico del ProblemDetail, nunca trazas.
        this.errorInfo = mensajeDeError(err, 'No fue posible realizar la busqueda.');
      }
    });
  }

  verComprobante(t: Transaccion): void {
    this.txSeleccionada = t;
  }

  cerrarComprobante(): void {
    this.txSeleccionada = null;
  }

  /**
   * El backend persiste el concepto con entidades HTML codificadas (defensa en profundidad).
   * Para mostrarlo legible se decodifican esas 5 entidades a texto; el resultado se pinta con
   * interpolacion {{ }}, por lo que Angular lo vuelve a tratar como texto y nunca como HTML.
   */
  textoPlano(valor: string | null | undefined): string {
    if (!valor) return '';
    return valor
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#x27;/g, "'")
      .replace(/&amp;/g, '&');
  }
}

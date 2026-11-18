import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { BancoService } from '../../services/banco.service';
import { Cuenta } from '../../models/banco.model';
import { mensajeDeError } from '../../services/errores';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule],
  templateUrl: './dashboard.component.html'
})
export class DashboardComponent implements OnInit {
  misCuentas: Cuenta[] = [];
  cuentaEspiada: Cuenta | null = null;
  cuentaIdAInspeccionar: number = 3; // Cuenta de otro cliente: debe responder 403
  loading = false;
  errorMsg = '';
  auditErrorMsg = '';

  constructor(
    public authService: AuthService,
    private bancoService: BancoService
  ) {}

  ngOnInit(): void {
    this.cargarMisCuentas();
  }

  cargarMisCuentas(): void {
    const user = this.authService.currentUser();
    if (!user) return;

    this.loading = true;
    this.bancoService.obtenerCuentasUsuario(user.usuarioId).subscribe({
      next: (cuentas) => {
        this.misCuentas = cuentas;
        this.loading = false;
      },
      error: (err) => {
        this.loading = false;
        this.errorMsg = mensajeDeError(err, 'No fue posible cargar sus cuentas.');
      }
    });
  }

  // [REMEDIACION 3.2] Verificacion del control anti-IDOR: una cuenta ajena retorna 403 Forbidden.
  inspeccionarCuentaPorId(): void {
    this.auditErrorMsg = '';
    this.cuentaEspiada = null;

    this.bancoService.obtenerCuentaPorId(this.cuentaIdAInspeccionar).subscribe({
      next: (cuenta) => {
        this.cuentaEspiada = cuenta;
      },
      error: (err) => {
        this.auditErrorMsg = 'HTTP ' + err.status + ' - ' + mensajeDeError(err, 'Consulta rechazada.');
      }
    });
  }
}


-- ==============================================================================
-- Datos Iniciales de Prueba - InsecurePay Digital Banking Portal
-- [REMEDIACION 4.1] Contrasenas almacenadas como hash BCrypt ($2a$, factor de trabajo 12).
-- Ninguna contrasena se persiste en texto plano.
-- ==============================================================================

INSERT INTO USUARIOS (username, password, nombre_completo, email, rol) VALUES
('admin', '$2a$12$cN8BU8L.4/IHI1mP9HWxLel.mPMrNGL4NEv5P7qGR9F5Qc7KN7o6y', 'Administrador General de Sistemas', 'admin@insecurepay.fi.cr', 'ADMIN'),
('auditor_seguridad', '$2a$12$EgMy0h875aOlgAfJGcriveqUjo59csy7sc/yVvQc3E16K79M.9dwi', 'Lic. Esteban Solano Chaves', 'esolano@insecurepay.fi.cr', 'AUDITOR'),
('carlos_mora', '$2a$12$QBfPPcJj.uk5ex1VGoTcp.uI9vqWt6xty.kIINd.V53cMTgdXtu7W', 'Carlos Mora Morales', 'cmora@correo.cr', 'CLIENTE'),
('maria_rojas', '$2a$12$m4AXd.N4XblmgMcmuBW96eWXTKhcvRVBZU2ETxlouh0mu620HoLmu', 'María Rojas Soto', 'mrojas@empresa.cr', 'CLIENTE'),
('juan_perez', '$2a$12$ZIj8XhkMzuJypQCaLry5b.GYJARrCmaUrN9K.UWf7hFNkLDQKILkq', 'Juan Pérez Delgado', 'jperez@correo.cr', 'CLIENTE');

INSERT INTO CUENTAS_BANCARIAS (usuario_id, numero_cuenta, tipo_cuenta, saldo, moneda, activa) VALUES
(1, 'CR05015202001026458900', 'CORRIENTE', 50000000.00, 'CRC', TRUE),
(3, 'CR05015202001026458901', 'AHORROS', 250000.00, 'CRC', TRUE),
(4, 'CR05015202001026458902', 'CORRIENTE', 4850000.00, 'CRC', TRUE),
(5, 'CR05015202001026458903', 'AHORROS', 75000.00, 'CRC', TRUE);

-- [REMEDIACION 3.3] Los conceptos se almacenan como texto plano (sin marcado HTML).
INSERT INTO TRANSACCIONES (cuenta_origen_id, cuenta_destino_id, monto, concepto_html, fecha, estado) VALUES
(2, 3, 45000.00, 'Pago de servicios profesionales de programacion. Verificado.', '2026-03-01 10:15:00', 'COMPLETADA'),
(3, 4, 120000.00, 'Cancelacion cuota de alquiler oficina central. Factura electronica #8849.', '2026-03-05 14:30:00', 'COMPLETADA'),
(3, 2, 15000.00, 'Reembolso almuerzo equipo de trabajo.', '2026-03-12 11:20:00', 'COMPLETADA'),
(4, 2, 35000.00, 'Aporte fondo solidario cooperativo. Transferencia inmediata SINPE Movil.', '2026-03-20 09:45:00', 'COMPLETADA');

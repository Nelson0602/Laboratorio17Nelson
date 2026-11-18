# Bitácora Pericial Forense — InsecurePay

**Curso:** IF0009 – Desarrollo de Software IV · UCR Sede del Atlántico, Recinto Paraíso
**Laboratorio 17:** Auditoría Forense de Software, Detección OWASP Top 10 y Remediación Defensiva
**Estudiante:** Nelson ___________________ · **Carné:** __________
**Fecha de la auditoría:** 18 de noviembre de 2026
**Objeto auditado:** `unsecure_web_app_lab` (commit base `ef19c14`) — Backend Spring Boot 3.3.4 / Java 21, Frontend Angular, H2 en memoria

---

## 0. Resumen ejecutivo

| ID | Vulnerabilidad | OWASP 2021 | CWE | CVSS v3.1 | Estado |
|----|----------------|-----------|-----|-----------|--------|
| HALLAZGO-01 | Inyección SQL en la búsqueda de transacciones | A03 – Injection | CWE-89 | **7.5 Alta** | Remediado |
| HALLAZGO-02 | IDOR/BOLA en saldos, cuentas y transferencias | A01 – Broken Access Control | CWE-639 / CWE-862 | **9.1 Crítica** | Remediado |
| HALLAZGO-03 | XSS almacenado en el concepto del comprobante | A03 – Injection | CWE-79 | **7.6 Alta** | Remediado |
| HALLAZGO-04 | Contraseñas almacenadas y comparadas en texto plano | A02 – Cryptographic Failures / A07 | CWE-256 / CWE-916 | **7.4 Alta** | Remediado |
| HALLAZGO-05 | Fuga de trazas técnicas, consola H2 expuesta y secreto JWT quemado | A05 – Security Misconfiguration / A02 | CWE-209 / CWE-798 / CWE-321 | **9.8 Crítica** (componente H2) | Remediado |

**Verificación global del "después":**
- `mvn clean test` → **12 pruebas, 0 fallos, BUILD SUCCESS** ([docs/evidencias/salida_mvn_clean_test.txt](docs/evidencias/salida_mvn_clean_test.txt)). Las 11 pruebas de [SeguridadRemediacionTests.java](backend/src/test/java/cr/ac/ucr/if0009/insecurepay/SeguridadRemediacionTests.java) cubren los 5 hallazgos.
- Pruebas DAST con `curl` contra el backend remediado en ejecución → [docs/evidencias/salida_despues.txt](docs/evidencias/salida_despues.txt) (script reproducible: [docs/evidencias/verificar_remediacion.sh](docs/evidencias/verificar_remediacion.sh)).
- `ng build` del frontend → compilación exitosa, sin `bypassSecurityTrust*` ni `[innerHTML]` en el código.

### 0.1 Metodología aplicada

1. **Reconocimiento:** inventario de controladores REST (`/api/auth`, `/api/cuentas`, `/api/transacciones`), DTOs, entidades JPA y `schema.sql`/`data.sql`.
2. **SAST:** revisión manual de servicios, repositorios, configuración y componentes Angular (búsqueda de `createNativeQuery`, concatenación de strings, `bypassSecurityTrustHtml`, `equals()` sobre contraseñas, propiedades `server.error.*`).
3. **DAST:** peticiones HTTP con `curl` y con la interfaz web (DevTools → Red).
4. **PoC:** reproducción controlada y no destructiva en el entorno local del laboratorio.
5. **Registro:** una ficha por hallazgo (plantilla 1.2 del enunciado).
6. **Remediación y verificación:** parche, pruebas automatizadas de regresión y nueva ejecución DAST.

### 0.2 Diferencias entre el enunciado y el código real

El código del repositorio difiere en algunos detalles del PDF; las PoC se ajustaron al código real:

| Enunciado (PDF) | Código real del repositorio |
|---|---|
| Paquete `cr.ac.ucr.insecurepay` | `cr.ac.ucr.if0009.insecurepay` |
| `carlos_mora` / `carlos2026`, cuentas ID 1 y 2 | `carlos_mora` / `carlos123`, cuenta **ID 2** (la ID 1 es de `admin`) |
| Cuenta de `maria_rojas` = ID 3 | Correcto: **ID 3**, saldo CRC 4 850 000,00 |
| Endpoint `GET /api/cuentas/{id}/saldo` | No existía. Se agregó en la versión remediada **con** control de propiedad |
| Campo `concepto` / columna `CONCEPTO_HTML` | Campo `conceptoHtml` / columna `concepto_html` |
| `app.jwt.secret=ClaveSuperSecreta...` | `jwt.secret=ClaveSecretaSuperDebilInsecurePayBanco2026` |
| Método `buscarPorTermino` | Se llamaba `buscarPorConcepto` |

> **Nota para la entrega:** en cada ficha, la sección "Antes" incluye el código vulnerable (evidencia SAST) y el comando PoC del enunciado. Las **capturas de pantalla del Antes** deben tomarse ejecutando el commit original `ef19c14` (`git checkout ef19c14`) y pegarse en los recuadros marcados con 📷.

---

## HALLAZGO-01 — Inyección SQL en la búsqueda de transacciones

| Campo pericial | Especificación técnica |
|---|---|
| **Identificador** | HALLAZGO-01 |
| **Nombre** | Inyección SQL en la búsqueda de transacciones (`GET /api/transacciones/buscar`) |
| **Clasificación OWASP** | A03:2021 – Injection (CWE-89) |
| **Severidad CVSS v3.1** | **7.5 Alta** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (el endpoint no pedía autenticación) |
| **Archivo y línea afectada** | `backend/src/main/java/cr/ac/ucr/if0009/insecurepay/service/TransaccionService.java` líneas 53–66 (concatenación en 55–56, ejecución en 60) |
| **Descripción del vector** | El parámetro `termino` llega sin validar desde la query string y se concatena dentro de una sentencia SQL nativa (`createNativeQuery`). Una comilla simple cierra el literal `LIKE` y permite alterar el predicado `WHERE` del motor H2. |
| **Impacto de negocio** | Pérdida de confidencialidad: cualquiera obtiene el historial de **todos** los clientes (montos, titulares, IBAN, conceptos). También facilita el reconocimiento del esquema de la BD. |

### Antes (explotación exitosa)

Código vulnerable (SAST):
```java
// TransaccionService.java (original) líneas 54-61
public List<TransaccionDto> buscarPorConcepto(String termino) {
    String sql = "SELECT * FROM TRANSACCIONES WHERE concepto_html LIKE '%" + termino
               + "%' OR estado LIKE '%" + termino + "%'";
    System.out.println("[AUDITORIA FORENSE INSECUREPAY] Ejecutando consulta SQL vulnerable: " + sql);
    List<Transaccion> resultados = entityManager.createNativeQuery(sql, Transaccion.class)
            .getResultList();
```

PoC (comando del enunciado):
```bash
curl -G -X GET http://localhost:8080/api/transacciones/buscar \
  --data-urlencode "termino=' OR 1=1 --" -H "Accept: application/json"
```
Resultado esperado en la versión vulnerable: HTTP 200 con las 4 transacciones de la BD, incluida la #2 (María → Juan), ajena a Carlos.

> 📷 **Captura Antes:** pegar aquí la salida del comando y/o la pantalla *Movimientos* con el payload.

### Remediación aplicada

1. **JPQL parametrizado con parámetro con nombre** en [TransaccionRepository.java](backend/src/main/java/cr/ac/ucr/if0009/insecurepay/repository/TransaccionRepository.java):
```java
@Query("SELECT t FROM Transaccion t " +
       "WHERE LOWER(t.conceptoHtml) LIKE LOWER(CONCAT('%', :termino, '%')) " +
       "   OR LOWER(t.estado) LIKE LOWER(CONCAT('%', :termino, '%')) " +
       "ORDER BY t.fecha DESC")
List<Transaccion> buscarPorTerminoSeguro(@Param("termino") String termino);
```
2. **Servicio refactorizado** ([TransaccionService.java](backend/src/main/java/cr/ac/ucr/if0009/insecurepay/service/TransaccionService.java) `buscarPorTermino`): se eliminaron `EntityManager`/`createNativeQuery` y el `System.out` que imprimía el SQL; se valida término vacío y longitud máxima (100); exige JWT y, para clientes, usa `buscarPorTerminoSeguroDeUsuario` (solo transacciones propias).
3. La columna `concepto_html` pasó de `CLOB` a `VARCHAR(4000)` para permitir `LOWER()` en JPQL y limitar el tamaño.

**Justificación:** con *bind parameters*, Hibernate envía `termino` como dato de un `PreparedStatement`: el motor nunca lo interpreta como código SQL (OWASP SQL Injection Prevention Cheat Sheet, defensa #1).

### Después (bloqueo defensivo confirmado)
```
HALLAZGO-01 | Busqueda con payload ' OR 1=1 -- (debe retornar [] )
[]
HTTP 200

HALLAZGO-01 | Busqueda legitima 'reembolso' (solo transacciones propias)
[{"id":3, ... "conceptoHtml":"Reembolso almuerzo equipo de trabajo.", ...}]
HTTP 200
```
Pruebas automatizadas: `sqlInjectionNeutralizada`, `busquedaLegitimaAcotada` ✅

---

## HALLAZGO-02 — IDOR / BOLA en cuentas, saldos y transferencias

| Campo pericial | Especificación técnica |
|---|---|
| **Identificador** | HALLAZGO-02 |
| **Nombre** | Referencia directa insegura a objetos en `GET /api/cuentas/{id}`, `GET /api/cuentas/usuario/{usuarioId}`, `GET /api/cuentas` y `POST /api/transacciones/transferir` |
| **Clasificación OWASP** | A01:2021 – Broken Access Control (CWE-639, CWE-862) |
| **Severidad CVSS v3.1** | **9.1 Crítica** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Archivo y línea afectada** | `controller/CuentaController.java` líneas 22–39; `service/CuentaService.java` líneas 22–42; `service/TransaccionService.java` líneas 76–78 (`findById(dto.getCuentaOrigenId())` sin validar propiedad); `frontend/.../transferir.component.ts` línea 18 |
| **Descripción del vector** | El backend usa ciegamente el `id` recibido en la URL o en el cuerpo. No valida el JWT ni coteja que la cuenta pertenezca al solicitante. Además, el frontend nunca enviaba el token y `GET /api/cuentas` devolvía todas las cuentas del banco. |
| **Impacto de negocio** | Confidencialidad: exposición del saldo y del IBAN de cualquier cliente. **Integridad financiera:** un cliente puede debitar fondos de cuentas ajenas hacia la suya (fraude directo). |

### Antes (explotación exitosa)

Código vulnerable (SAST):
```java
// CuentaService.java (original) líneas 30-34
public CuentaDto obtenerPorId(Long id) {
    CuentaBancaria cuenta = cuentaRepository.findById(id)
            .orElseThrow(() -> new RuntimeException("Cuenta bancaria no encontrada con ID: " + id));
    return convertirADto(cuenta);
}
// TransaccionService.java (original) líneas 76-78
// IDOR: No se valida si cuentaOrigenId pertenece al usuario autenticado en la sesion
CuentaBancaria cuentaOrigen = cuentaRepository.findById(dto.getCuentaOrigenId()) ...
```

PoC (enunciado, ajustado al código real: en el original no existía `/saldo`, se usa `/api/cuentas/3`):
```bash
curl -X GET http://localhost:8080/api/cuentas/3 -H "Authorization: Bearer <TOKEN_CARLOS>"
```
Resultado esperado en la versión vulnerable: HTTP 200 con `"titular":"María Rojas Soto"` y `"saldo":4850000.00`. Desde la vista *Transferir*, el selector de origen permitía elegir la cuenta #3 de María y el servidor aceptaba el débito (HTTP 201).

> 📷 **Captura Antes:** pegar la respuesta 200 con el saldo de María y la transferencia aceptada desde su cuenta.

### Remediación aplicada

1. **Identidad verificada desde el JWT:** nuevo [SesionService.java](backend/src/main/java/cr/ac/ucr/if0009/insecurepay/service/SesionService.java) extrae el token de `Authorization: Bearer`, valida firma y expiración (`JwtUtil.extraerUsername`) y carga el usuario desde la BD (el rol sale de la BD, no de claims).
2. **Validación estricta de propiedad** en [CuentaService.java](backend/src/main/java/cr/ac/ucr/if0009/insecurepay/service/CuentaService.java):
```java
public CuentaDto obtenerCuentaSegura(Long cuentaId, String authHeader) {
    Usuario usuario = sesionService.usuarioAutenticado(authHeader);          // 1. JWT
    CuentaBancaria cuenta = cuentaRepository.findById(cuentaId)              // 2. Buscar
            .orElseThrow(() -> new RecursoNoEncontradoException("Cuenta bancaria no existe."));
    if (!sesionService.esPropietario(usuario, cuenta)                        // 3. Propiedad
            && !sesionService.esPrivilegiado(usuario)) {                     //    (ADMIN/AUDITOR)
        throw new AccesoDenegadoException("Acceso no autorizado a cuenta ajena.");
    }
    return mapearDto(cuenta);
}
```
3. **Transferencias** ([TransaccionService.java](backend/src/main/java/cr/ac/ucr/if0009/insecurepay/service/TransaccionService.java) `transferir`): antes de debitar se exige que la cuenta de origen pertenezca al usuario del token (ni ADMIN ni AUDITOR pueden debitar cuentas ajenas):
```java
if (!sesionService.esPropietario(usuario, cuentaOrigen)) {
    throw new AccesoDenegadoException("Fraude detectado: no puede debitar fondos de cuentas ajenas.");
}
```
   También se validan cuenta destino distinta de la de origen, fondos suficientes y monto positivo.
4. Se aplicó el mismo control a `/api/cuentas/usuario/{id}`, `/api/cuentas` (un cliente solo ve sus cuentas), `/api/transacciones`, `/api/transacciones/{id}` y `/api/transacciones/cuenta/{id}`. Se agregó `/api/cuentas/{id}/saldo` ya protegido.
5. `AccesoDenegadoException` → **HTTP 403 Forbidden**; token ausente o inválido → **HTTP 401** (ProblemDetail).
6. **Frontend:** [auth.interceptor.ts](frontend/src/app/services/auth.interceptor.ts) adjunta el `Bearer` a cada petición; [auth.guard.ts](frontend/src/app/services/auth.guard.ts) protege las rutas; la vista *Transferir* solo lista las cuentas propias.

**Justificación:** la autorización se decide en el servidor con una identidad que el cliente no puede falsificar (JWT firmado con HMAC-SHA256). El ID de la URL o del cuerpo solo indica *qué* recurso se pide, nunca *quién* lo pide (OWASP Authorization Cheat Sheet / API1:2023 BOLA).

### Después (bloqueo defensivo confirmado)
```
HALLAZGO-02 | carlos consulta saldo de cuenta 3 (maria) -> 403
{"type":".../acceso-denegado","title":"Acceso denegado","status":403,"detail":"Acceso no autorizado a cuenta ajena.","instance":"/api/cuentas/3/saldo",...}
HTTP 403

HALLAZGO-02 | carlos consulta su propia cuenta 2 -> 200
{"cuentaId":2,"numeroCuenta":"CR05015202001026458901","saldo":250000.00,"moneda":"CRC"}
HTTP 200

HALLAZGO-02 | Consulta sin token -> 401
HTTP 401

HALLAZGO-02 | carlos intenta debitar la cuenta 3 (maria) -> 403
{"...","status":403,"detail":"Fraude detectado: no puede debitar fondos de cuentas ajenas.",...}
HTTP 403
```
Pruebas automatizadas: `idorSaldoBloqueado`, `propietarioConsultaSuCuenta`, `sinTokenNoAutenticado`, `idorTransferenciaBloqueada` (además verifica que el saldo de María sigue en 4 850 000,00) ✅

---

## HALLAZGO-03 — Cross-Site Scripting almacenado en el comprobante

| Campo pericial | Especificación técnica |
|---|---|
| **Identificador** | HALLAZGO-03 |
| **Nombre** | XSS almacenado en el concepto de la transferencia (vista *Ver Comprobante*) |
| **Clasificación OWASP** | A03:2021 – Injection (CWE-79) |
| **Severidad CVSS v3.1** | **7.6 Alta** — `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N` |
| **Archivo y línea afectada** | Backend: `service/TransaccionService.java` línea 98 (`setConceptoHtml(dto.getConceptoHtml())`). Frontend: `components/transacciones/transacciones.component.ts` líneas 81–85 (`bypassSecurityTrustHtml`) y `transacciones.component.html` línea 101 (`[innerHTML]`) |
| **Descripción del vector** | El concepto se persiste sin codificar y el frontend desactiva a propósito el saneamiento de Angular con `bypassSecurityTrustHtml`, inyectando el contenido como HTML activo. Un manejador de eventos dentro del concepto se ejecuta en el navegador de quien abra el comprobante. |
| **Impacto de negocio** | Ejecución de JavaScript en la sesión de la víctima (el destinatario o un auditor): lectura del JWT en `localStorage` y suplantación de la sesión, desfiguración de comprobantes oficiales, phishing dentro del portal. |

### Antes (explotación exitosa)

Código vulnerable (SAST):
```ts
// transacciones.component.ts (original) líneas 81-85
if (t.conceptoHtml) {
  this.conceptoSeguro = this.sanitizer.bypassSecurityTrustHtml(t.conceptoHtml);
}
```
```html
<!-- transacciones.component.html (original) línea 100-101 -->
<div ... [innerHTML]="conceptoSeguro"></div>
```
PoC: seguir los pasos 1–6 del Caso 3 del enunciado (módulo *Transferir* → concepto con el vector `<img src="x" onerror=...>` → *Movimientos* → *Ver Comprobante*). En la versión vulnerable aparece el cuadro `alert()`.

> 📷 **Captura Antes:** pegar la ventana emergente `alert` sobre el comprobante.

### Remediación aplicada

1. **Frontend** ([transacciones.component.ts](frontend/src/app/components/transacciones/transacciones.component.ts) y [.html](frontend/src/app/components/transacciones/transacciones.component.html)): se eliminaron `DomSanitizer`, `bypassSecurityTrustHtml` y `[innerHTML]`. El concepto se pinta con **interpolación segura**:
```html
<div class="comprobante-concepto">{{ textoPlano(txSeleccionada.conceptoHtml) }}</div>
```
   `textoPlano()` solo decodifica las 5 entidades que agrega el backend para que el texto se lea bien; el resultado vuelve a pasar por `{{ }}`, que Angular siempre trata como texto (`<` → `&lt;`).
2. **Backend, defensa en profundidad** ([TransaccionService.java](backend/src/main/java/cr/ac/ucr/if0009/insecurepay/service/TransaccionService.java)): antes de persistir se codifican los metacaracteres HTML y se limita la longitud a 500:
```java
static String sanitizarTexto(String entrada) {
    if (entrada == null) return "";
    return entrada.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                  .replace("\"", "&quot;").replace("'", "&#x27;");
}
```
3. Los datos semilla de `data.sql` ya no contienen marcado HTML.

**Justificación:** el dato del usuario nunca llega al DOM como HTML. Se cumple la regla #1 del OWASP XSS Prevention Cheat Sheet (codificación de salida según contexto) y se mantiene el saneamiento nativo de Angular activo.

### Después (bloqueo defensivo confirmado)
```
HALLAZGO-03 | Concepto con etiquetas HTML se persiste codificado
{"id":5, ... "conceptoHtml":"Pago de Servicios &lt;img src=x onerror=alert(1)&gt;", ...}
HTTP 201
```
En la interfaz, el comprobante muestra el texto literal `Pago de Servicios <img src=x onerror=alert(1)>` y no se ejecuta ningún script.

> 📷 **Captura Después:** pegar el comprobante con el texto literal y sin ventana emergente.

Prueba automatizada: `xssAlmacenadoCodificado` ✅

---

## HALLAZGO-04 — Contraseñas en texto plano (Reto 4.1)

| Campo pericial | Especificación técnica |
|---|---|
| **Identificador** | HALLAZGO-04 |
| **Nombre** | Almacenamiento y comparación de contraseñas en texto plano |
| **Clasificación OWASP** | A02:2021 – Cryptographic Failures; A07:2021 – Identification and Authentication Failures (CWE-256, CWE-916, CWE-204) |
| **Severidad CVSS v3.1** | **7.4 Alta** — `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` (se explota al combinarse con otra fuga, p. ej. la consola H2 abierta o la SQLi) |
| **Archivo y línea afectada** | `service/AuthService.java` línea 27 (`usuario.getPassword().equals(request.getPassword())`); `resources/data.sql` líneas 7–11; `model/Usuario.java` líneas 16–19 |
| **Descripción del vector** | Las contraseñas se guardan tal cual en la tabla `USUARIOS` y se comparan con `String.equals()`. Además, los mensajes de error distinguían "Usuario no encontrado" de "Credenciales inválidas", lo que permitía enumerar usuarios. |
| **Impacto de negocio** | Cualquier lectura de la BD (consola H2, SQLi, respaldo filtrado) revela todas las credenciales en claro, incluidas las de `admin`. Habilita la toma de cuentas y el relleno de credenciales (*credential stuffing*) en otros servicios. |

### Antes (explotación exitosa)
```java
// AuthService.java (original) líneas 24-29
Usuario usuario = usuarioRepository.findByUsername(request.getUsername())
        .orElseThrow(() -> new RuntimeException("Usuario no encontrado en InsecurePay: " + request.getUsername()));
if (!usuario.getPassword().equals(request.getPassword())) {
    throw new RuntimeException("Credenciales invalidas para el usuario: " + request.getUsername());
}
```
```sql
-- data.sql (original) línea 9
('carlos_mora', 'carlos123', 'Carlos Mora Morales', 'cmora@correo.cr', 'CLIENTE'),
```
Evidencia DAST: con la consola H2 abierta (`/h2-console`, usuario `sa` sin contraseña) la consulta `SELECT username, password FROM USUARIOS` devolvía las contraseñas en claro.

> 📷 **Captura Antes:** pegar la tabla `USUARIOS` con contraseñas legibles.

### Remediación aplicada

1. **Bean de BCrypt** en [SecurityConfig.java](backend/src/main/java/cr/ac/ucr/if0009/insecurepay/config/SecurityConfig.java) (dependencia `spring-security-crypto`, sin activar la cadena de filtros completa de Spring Security):
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);   // factor de trabajo 12 (>= 10 exigido)
}
```
2. **Hashes en `data.sql`** ([data.sql](backend/src/main/resources/data.sql)), generados con `BCryptPasswordEncoder(12)`. Cada uno tiene sal aleatoria propia:
```sql
('carlos_mora', '$2a$12$QBfPPcJj.uk5ex1VGoTcp.uI9vqWt6xty.kIINd.V53cMTgdXtu7W', ...),
```
3. **Validación exclusiva con `matches`** en [AuthService.java](backend/src/main/java/cr/ac/ucr/if0009/insecurepay/service/AuthService.java):
```java
Optional<Usuario> encontrado = usuarioRepository.findByUsername(request.getUsername());
String hashAlmacenado = encontrado.map(Usuario::getPassword).orElse(hashSenuelo);
boolean coincide = passwordEncoder.matches(request.getPassword(), hashAlmacenado);
if (encontrado.isEmpty() || !coincide) {
    throw new CredencialesInvalidasException("Usuario o contrasena incorrectos.");
}
```
   Mensaje genérico y hash señuelo para que el tiempo de respuesta sea igual exista o no el usuario (evita la enumeración).
4. **Ninguna contraseña se persiste ni viaja en claro de vuelta:** `LoginResponse` no incluye contraseña ni hash, se eliminaron los `System.out` y `spring.jpa.show-sql=false`. En tránsito, la contraseña del login debe ir sobre HTTPS en producción (ver riesgos residuales).

**Credenciales de prueba (sin cambios para el evaluador):** `admin/admin123`, `auditor_seguridad/auditor2026`, `carlos_mora/carlos123`, `maria_rojas/maria123`, `juan_perez/juan123`.

### Después (bloqueo defensivo confirmado)
```
HALLAZGO-04 | Login con BCrypt (credenciales validas -> 200, respuesta sin contrasena)
{"token":"<JWT omitido>","username":"carlos_mora","nombreCompleto":"Carlos Mora Morales","rol":"CLIENTE","usuarioId":3}
HTTP 200

HALLAZGO-04 | Login con contrasena incorrecta -> 401 mensaje generico
{"type":".../no-autenticado","title":"Autenticacion requerida","status":401,"detail":"Usuario o contrasena incorrectos.",...}
HTTP 401
```
Pruebas automatizadas: `contrasenasBcrypt` (todas las filas cumplen `^\$2[aby]\$(1[0-9]|[2-3][0-9])\$.{53}$`, `matches()` es verdadero y la respuesta no contiene `$2a$`) y `loginInvalidoGenerico` ✅

---

## HALLAZGO-05 — Fuga de trazas técnicas, consola H2 expuesta y secreto JWT quemado (Reto 4.2)

| Campo pericial | Especificación técnica |
|---|---|
| **Identificador** | HALLAZGO-05 |
| **Nombre** | Configuración insegura: stack traces en respuestas HTTP, consola H2 pública y clave JWT predecible en el repositorio |
| **Clasificación OWASP** | A05:2021 – Security Misconfiguration; A02:2021 – Cryptographic Failures (CWE-209, CWE-215, CWE-798, CWE-321) |
| **Severidad CVSS v3.1** | Trazas: **5.3 Media** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` · Consola H2 abierta a la red sin contraseña: **9.8 Crítica** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` · Secreto JWT quemado: **9.1 Crítica** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` → severidad del hallazgo: **9.8 Crítica** |
| **Archivo y línea afectada** | `resources/application.properties` líneas 15–17 (H2), 28–30 (`include-stacktrace=always`, `include-message=always`, `include-binding-errors=always`), 34 (`jwt.secret=...`); `util/JwtUtil.java` líneas 18–19; uso generalizado de `RuntimeException` con datos internos en el mensaje |
| **Descripción del vector** | Ante cualquier excepción, Spring devolvía en el JSON de error el `trace` completo (paquetes, clases, consultas SQL de Hibernate). La consola H2 aceptaba conexiones remotas (`web-allow-others=true`) con usuario `sa` sin contraseña. La clave HMAC era una cadena legible guardada en el repositorio, así que cualquiera con acceso al código podía firmar tokens válidos. |
| **Impacto de negocio** | Reconocimiento facilitado para otros ataques (versiones, estructura interna, SQL). Control total de la BD vía consola H2. Falsificación de tokens JWT para suplantar a cualquier usuario, incluido `admin`. |

### Antes (explotación exitosa)
```properties
# application.properties (original)
spring.h2.console.enabled=true
spring.h2.console.settings.web-allow-others=true
server.error.include-message=always
server.error.include-stacktrace=always
server.error.include-binding-errors=always
jwt.secret=ClaveSecretaSuperDebilInsecurePayBanco2026
```
PoC: provocar un error, por ejemplo `curl http://localhost:8080/api/cuentas/abc` o el payload `'` en la búsqueda. La respuesta 500/400 incluía el campo `"trace": "org.springframework...` con el stack completo (en la búsqueda, el error `org.h2.jdbc.JdbcSQLSyntaxErrorException` exponía la sentencia SQL). El frontend además mostraba ese texto con la etiqueta "Fallo de Base de Datos (Stack Trace)".

> 📷 **Captura Antes:** pegar la respuesta JSON con el campo `trace` y la pantalla de la consola H2 accesible.

### Remediación aplicada

1. **`application.properties` endurecido** ([application.properties](backend/src/main/resources/application.properties)):
```properties
server.error.include-stacktrace=never
server.error.include-message=never
server.error.include-binding-errors=never
server.error.include-exception=false
server.error.whitelabel.enabled=false
spring.mvc.problemdetails.enabled=true
spring.h2.console.enabled=${H2_CONSOLE_ENABLED:false}
spring.h2.console.settings.web-allow-others=false
spring.jpa.show-sql=false
app.jwt.secret=${JWT_SECRET:}
app.cors.allowed-origins=${CORS_ALLOWED_ORIGINS:http://localhost:4200}
```
2. **Manejador global RFC 7807** [GlobalExceptionHandler.java](backend/src/main/java/cr/ac/ucr/if0009/insecurepay/exception/GlobalExceptionHandler.java) (`@RestControllerAdvice`, `@Order(HIGHEST_PRECEDENCE)`): traduce las excepciones de dominio (`AccesoDenegadoException` 403, `RecursoNoEncontradoException` 404, `CredencialesInvalidasException` 401, `SolicitudInvalidaException` 400) y los errores de Spring a `ProblemDetail` con `type`, `title`, `status`, `detail`, `instance` y `timestamp`. Cualquier otra excepción responde 500 con un mensaje genérico y un **identificador de incidente**; el detalle técnico solo queda en el log del servidor:
```java
@ExceptionHandler(Exception.class)
public ProblemDetail errorInterno(Exception ex) {
    String incidente = UUID.randomUUID().toString();
    log.error("Error interno no controlado [incidente={}]", incidente, ex);
    ProblemDetail pd = problema(HttpStatus.INTERNAL_SERVER_ERROR, "error-interno",
            "Error interno del servidor",
            "Ocurrio un error inesperado. Reporte el identificador de incidente a soporte.");
    pd.setProperty("incidente", incidente);
    return pd;
}
```
   Los mensajes de las excepciones ya no incluyen IDs, nombres de usuario ni datos internos.
3. **Secreto JWT externalizado** ([JwtUtil.java](backend/src/main/java/cr/ac/ucr/if0009/insecurepay/util/JwtUtil.java)): se lee de la variable de entorno `JWT_SECRET` (Base64 o texto) y **se rechaza el arranque si mide menos de 256 bits** (32 bytes). Si no está definida, se genera con `SecureRandom` una clave efímera de 512 bits (nunca una clave predecible) y se registra una advertencia. Expiración del token reducida de 24 h a 1 h (configurable con `JWT_EXPIRATION_MS`).
```bash
export JWT_SECRET=$(openssl rand -base64 48)   # 384 bits
```
4. **CORS** restringido a `http://localhost:4200` (antes `*`). El frontend solo muestra el `detail` del ProblemDetail ([errores.ts](frontend/src/app/services/errores.ts)) y nunca trazas.

**Justificación:** CWE-209 se mitiga entregando al cliente solo información genérica y estandarizada (RFC 7807), con correlación por identificador de incidente para soporte. CWE-798 y CWE-321 se mitigan sacando el secreto del código fuente (*12-Factor App*, configuración por entorno) y exigiendo la longitud mínima que RFC 7518 §3.2 pide para HS256.

### Después (bloqueo defensivo confirmado)
```
HALLAZGO-05 | Error de tipo de parametro -> ProblemDetail 400 sin stack trace
{"type":"https://insecurepay.ucr.ac.cr/problemas/solicitud-invalida","title":"Solicitud invalida","status":400,"detail":"Los parametros enviados no tienen un formato valido.","instance":"/api/cuentas/abc","timestamp":"..."}
HTTP 400

HALLAZGO-05 | Recurso inexistente -> ProblemDetail 404
{"type":".../recurso-no-encontrado","title":"Recurso no encontrado","status":404,"detail":"Cuenta bancaria no existe.","instance":"/api/cuentas/9999",...}
HTTP 404

HALLAZGO-05 | Consola H2 deshabilitada -> 404
HTTP 404
```
Pruebas automatizadas: `erroresSinFugaDeInformacion` (sin `trace`, `Exception`, `SELECT` ni `org.hibernate`; `Content-Type: application/problem+json`) y `consolaH2Deshabilitada` ✅

---

## 6. Lista de verificación de entrega

- [x] Backend compila sin errores (`mvn clean test` → 12/12 pruebas OK).
- [x] La búsqueda de transacciones usa JPQL parametrizado y resiste `' OR 1=1 --`.
- [x] Los endpoints de cuentas y transferencias bloquean solicitudes IDOR con **HTTP 403 Forbidden**.
- [x] El concepto de la transferencia no ejecuta scripts en la vista de comprobantes.
- [x] Las contraseñas en `data.sql` están codificadas con BCrypt (factor 12) y el login funciona.
- [x] `application.properties` no expone trazas ni detalles internos ante errores HTTP 500.
- [x] Este documento incluye la bitácora pericial de los 5 hallazgos *(faltan solo las capturas 📷 del "Antes")*.

## 7. Riesgos residuales y recomendaciones

1. **JWT en `localStorage`:** sigue siendo legible por JavaScript si apareciera otro XSS. Se recomienda una cookie `HttpOnly; Secure; SameSite=Strict` o un *Content-Security-Policy* estricto.
2. **Transporte:** desplegar únicamente sobre HTTPS/TLS 1.2+ con HSTS para que credenciales y tokens no viajen en claro.
3. **Autorización centralizada:** migrar a Spring Security (`SecurityFilterChain` + `@PreAuthorize`) para no depender de que cada endpoint invoque `SesionService`.
4. **Protección contra fuerza bruta:** limitar intentos de login por IP o usuario y bloquear temporalmente la cuenta.
5. **Operaciones financieras:** bloqueo optimista o pesimista (`@Version` / `SELECT ... FOR UPDATE`) para evitar condiciones de carrera en débitos concurrentes.
6. **Gestión de secretos:** en producción, `JWT_SECRET` y `DB_PASSWORD` deben venir de un gestor de secretos (Vault, AWS Secrets Manager, Azure Key Vault) con rotación periódica.

## 8. Cadena de custodia

| Elemento | Valor |
|---|---|
| Repositorio original | `jonnexusinsights-lab/unsecure_web_app_lab`, commit `ef19c14` (estado vulnerable, evidencia del "Antes") |
| Repositorio de entrega | `Nelson0602/Laboratorio17Nelson`, rama `main` (estado remediado) |
| Entorno | Windows 11, OpenJDK 25.0.4 (target Java 21), Maven 3.9.16, Node 24.21.0, H2 2.2.224 |
| Herramientas | Revisión manual de código (SAST), `curl` 8.x (DAST), JUnit 5 + MockMvc (regresión) |
| Evidencias | `docs/evidencias/salida_despues.txt`, `docs/evidencias/salida_mvn_clean_test.txt`, `docs/evidencias/verificar_remediacion.sh` |

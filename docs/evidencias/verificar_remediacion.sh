#!/usr/bin/env bash
# Verificacion DAST post-remediacion (Laboratorio 17). Requiere el backend en http://localhost:8080
API=http://localhost:8080/api
sep(){ echo; echo "=================================================================="; echo "$1"; echo "=================================================================="; }

TOKEN_CARLOS=$(curl -s -X POST $API/auth/login -H "Content-Type: application/json" \
  -d '{"username":"carlos_mora","password":"carlos123"}' | sed -E 's/.*"token":"([^"]+)".*/\1/')

sep "HALLAZGO-04 | Login con BCrypt (credenciales validas -> 200, respuesta sin contrasena)"
curl -s -w "\nHTTP %{http_code}\n" -X POST $API/auth/login -H "Content-Type: application/json" \
  -d '{"username":"carlos_mora","password":"carlos123"}' | sed -E 's/"token":"[^"]{20}[^"]*"/"token":"<JWT omitido>"/'
sep "HALLAZGO-04 | Login con contrasena incorrecta -> 401 mensaje generico"
curl -s -w "\nHTTP %{http_code}\n" -X POST $API/auth/login -H "Content-Type: application/json" \
  -d '{"username":"carlos_mora","password":"incorrecta"}'

sep "HALLAZGO-01 | Busqueda con payload ' OR 1=1 -- (debe retornar [] )"
curl -s -G -w "\nHTTP %{http_code}\n" $API/transacciones/buscar --data-urlencode "termino=' OR 1=1 --" \
  -H "Accept: application/json" -H "Authorization: Bearer $TOKEN_CARLOS"
sep "HALLAZGO-01 | Busqueda legitima 'reembolso' (solo transacciones propias)"
curl -s -G -w "\nHTTP %{http_code}\n" $API/transacciones/buscar --data-urlencode "termino=reembolso" \
  -H "Authorization: Bearer $TOKEN_CARLOS"

sep "HALLAZGO-02 | carlos consulta saldo de cuenta 3 (maria) -> 403"
curl -s -w "\nHTTP %{http_code}\n" $API/cuentas/3/saldo -H "Authorization: Bearer $TOKEN_CARLOS"
sep "HALLAZGO-02 | carlos consulta su propia cuenta 2 -> 200"
curl -s -w "\nHTTP %{http_code}\n" $API/cuentas/2/saldo -H "Authorization: Bearer $TOKEN_CARLOS"
sep "HALLAZGO-02 | Consulta sin token -> 401"
curl -s -w "\nHTTP %{http_code}\n" $API/cuentas/2
sep "HALLAZGO-02 | carlos intenta debitar la cuenta 3 (maria) -> 403"
curl -s -w "\nHTTP %{http_code}\n" -X POST $API/transacciones/transferir -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN_CARLOS" \
  -d '{"cuentaOrigenId":3,"numeroCuentaDestino":"CR05015202001026458901","monto":100000,"conceptoHtml":"prueba"}'

sep "HALLAZGO-03 | Concepto con etiquetas HTML se persiste codificado"
curl -s -w "\nHTTP %{http_code}\n" -X POST $API/transacciones/transferir -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN_CARLOS" \
  -d '{"cuentaOrigenId":2,"numeroCuentaDestino":"CR05015202001026458902","monto":1000,"conceptoHtml":"Pago de Servicios <img src=x onerror=alert(1)>"}'

sep "HALLAZGO-05 | Error de tipo de parametro -> ProblemDetail 400 sin stack trace"
curl -s -w "\nHTTP %{http_code}\n" $API/cuentas/abc -H "Authorization: Bearer $TOKEN_CARLOS"
sep "HALLAZGO-05 | Recurso inexistente -> ProblemDetail 404"
curl -s -w "\nHTTP %{http_code}\n" $API/cuentas/9999 -H "Authorization: Bearer $TOKEN_CARLOS"
sep "HALLAZGO-05 | Consola H2 deshabilitada -> 404"
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8080/h2-console

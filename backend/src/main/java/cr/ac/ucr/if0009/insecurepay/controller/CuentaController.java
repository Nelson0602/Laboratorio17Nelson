package cr.ac.ucr.if0009.insecurepay.controller;

import cr.ac.ucr.if0009.insecurepay.dto.CuentaDto;
import cr.ac.ucr.if0009.insecurepay.service.CuentaService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/cuentas")
public class CuentaController {

    private final CuentaService cuentaService;

    public CuentaController(CuentaService cuentaService) {
        this.cuentaService = cuentaService;
    }

    // [REMEDIACION A01:2021] Un cliente solo recibe sus cuentas; ADMIN/AUDITOR reciben todas.
    @GetMapping
    public ResponseEntity<List<CuentaDto>> listar(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
        return ResponseEntity.ok(cuentaService.listarVisibles(authHeader));
    }

    // [REMEDIACION A01:2021 - IDOR] Se valida la propiedad de la cuenta contra la identidad del JWT.
    @GetMapping("/{id}")
    public ResponseEntity<CuentaDto> obtenerPorId(
            @PathVariable Long id,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
        return ResponseEntity.ok(cuentaService.obtenerCuentaSegura(id, authHeader));
    }

    // [REMEDIACION A01:2021 - IDOR] Consulta de saldo con la misma validacion de propiedad.
    @GetMapping("/{id}/saldo")
    public ResponseEntity<Map<String, Object>> obtenerSaldo(
            @PathVariable Long id,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
        CuentaDto cuenta = cuentaService.obtenerCuentaSegura(id, authHeader);
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("cuentaId", cuenta.getId());
        resp.put("numeroCuenta", cuenta.getNumeroCuenta());
        resp.put("saldo", cuenta.getSaldo());
        resp.put("moneda", cuenta.getMoneda());
        return ResponseEntity.ok(resp);
    }

    // [REMEDIACION A01:2021 - BOLA] El usuarioId de la URL debe coincidir con el del JWT.
    @GetMapping("/usuario/{usuarioId}")
    public ResponseEntity<List<CuentaDto>> obtenerPorUsuario(
            @PathVariable Long usuarioId,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
        return ResponseEntity.ok(cuentaService.obtenerPorUsuarioSeguro(usuarioId, authHeader));
    }
}

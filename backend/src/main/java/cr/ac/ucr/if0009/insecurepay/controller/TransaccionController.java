package cr.ac.ucr.if0009.insecurepay.controller;

import cr.ac.ucr.if0009.insecurepay.dto.TransaccionDto;
import cr.ac.ucr.if0009.insecurepay.dto.TransferenciaDto;
import cr.ac.ucr.if0009.insecurepay.service.TransaccionService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/transacciones")
public class TransaccionController {

    private final TransaccionService transaccionService;

    public TransaccionController(TransaccionService transaccionService) {
        this.transaccionService = transaccionService;
    }

    @GetMapping
    public ResponseEntity<List<TransaccionDto>> listar(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
        return ResponseEntity.ok(transaccionService.listarVisibles(authHeader));
    }

    @GetMapping("/{id}")
    public ResponseEntity<TransaccionDto> obtenerPorId(
            @PathVariable Long id,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
        return ResponseEntity.ok(transaccionService.obtenerPorId(id, authHeader));
    }

    @GetMapping("/cuenta/{cuentaId}")
    public ResponseEntity<List<TransaccionDto>> obtenerPorCuenta(
            @PathVariable Long cuentaId,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
        return ResponseEntity.ok(transaccionService.obtenerPorCuenta(cuentaId, authHeader));
    }

    // [REMEDIACION A03:2021 - SQL Injection] Busqueda mediante JPQL parametrizado.
    @GetMapping("/buscar")
    public ResponseEntity<List<TransaccionDto>> buscar(
            @RequestParam("termino") String termino,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
        return ResponseEntity.ok(transaccionService.buscarPorTermino(termino, authHeader));
    }

    // [REMEDIACION A01:2021 - IDOR] y [REMEDIACION A03:2021 - Stored XSS]
    @PostMapping("/transferir")
    public ResponseEntity<TransaccionDto> transferir(
            @RequestBody TransferenciaDto dto,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
        return ResponseEntity.status(HttpStatus.CREATED).body(transaccionService.transferir(dto, authHeader));
    }
}

package cr.ac.ucr.if0009.insecurepay.service;

import cr.ac.ucr.if0009.insecurepay.dto.CuentaDto;
import cr.ac.ucr.if0009.insecurepay.exception.AccesoDenegadoException;
import cr.ac.ucr.if0009.insecurepay.exception.RecursoNoEncontradoException;
import cr.ac.ucr.if0009.insecurepay.model.CuentaBancaria;
import cr.ac.ucr.if0009.insecurepay.model.Usuario;
import cr.ac.ucr.if0009.insecurepay.repository.CuentaRepository;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * [REMEDIACION 3.2 - A01:2021 IDOR / BOLA / CWE-639]
 * Toda consulta valida que la cuenta pertenezca al usuario del JWT
 * (o que el solicitante tenga rol ADMIN / AUDITOR).
 */
@Service
public class CuentaService {

    private final CuentaRepository cuentaRepository;
    private final SesionService sesionService;

    public CuentaService(CuentaRepository cuentaRepository, SesionService sesionService) {
        this.cuentaRepository = cuentaRepository;
        this.sesionService = sesionService;
    }

    /** Listado global restringido a roles privilegiados; un cliente solo ve sus propias cuentas. */
    public List<CuentaDto> listarVisibles(String authHeader) {
        Usuario usuario = sesionService.usuarioAutenticado(authHeader);
        List<CuentaBancaria> cuentas = sesionService.esPrivilegiado(usuario)
                ? cuentaRepository.findAll()
                : cuentaRepository.findByUsuarioId(usuario.getId());
        return cuentas.stream().map(this::mapearDto).toList();
    }

    public CuentaDto obtenerCuentaSegura(Long cuentaId, String authHeader) {
        // 1. Identidad verificada desde el JWT
        Usuario usuario = sesionService.usuarioAutenticado(authHeader);

        // 2. Buscar la cuenta
        CuentaBancaria cuenta = cuentaRepository.findById(cuentaId)
                .orElseThrow(() -> new RecursoNoEncontradoException("Cuenta bancaria no existe."));

        // 3. Validar propiedad estricta
        if (!sesionService.esPropietario(usuario, cuenta) && !sesionService.esPrivilegiado(usuario)) {
            throw new AccesoDenegadoException("Acceso no autorizado a cuenta ajena.");
        }
        return mapearDto(cuenta);
    }

    public List<CuentaDto> obtenerPorUsuarioSeguro(Long usuarioId, String authHeader) {
        Usuario usuario = sesionService.usuarioAutenticado(authHeader);
        if (!usuario.getId().equals(usuarioId) && !sesionService.esPrivilegiado(usuario)) {
            throw new AccesoDenegadoException("Acceso no autorizado a cuentas de otro cliente.");
        }
        return cuentaRepository.findByUsuarioId(usuarioId).stream().map(this::mapearDto).toList();
    }

    private CuentaDto mapearDto(CuentaBancaria cuenta) {
        CuentaDto dto = new CuentaDto();
        dto.setId(cuenta.getId());
        dto.setUsuarioId(cuenta.getUsuario().getId());
        dto.setTitular(cuenta.getUsuario().getNombreCompleto());
        dto.setNumeroCuenta(cuenta.getNumeroCuenta());
        dto.setTipoCuenta(cuenta.getTipoCuenta().name());
        dto.setSaldo(cuenta.getSaldo());
        dto.setMoneda(cuenta.getMoneda());
        dto.setActiva(cuenta.getActiva());
        return dto;
    }
}

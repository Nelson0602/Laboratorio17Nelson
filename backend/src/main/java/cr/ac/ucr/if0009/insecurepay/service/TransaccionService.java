package cr.ac.ucr.if0009.insecurepay.service;

import cr.ac.ucr.if0009.insecurepay.dto.TransaccionDto;
import cr.ac.ucr.if0009.insecurepay.dto.TransferenciaDto;
import cr.ac.ucr.if0009.insecurepay.exception.AccesoDenegadoException;
import cr.ac.ucr.if0009.insecurepay.exception.RecursoNoEncontradoException;
import cr.ac.ucr.if0009.insecurepay.exception.SolicitudInvalidaException;
import cr.ac.ucr.if0009.insecurepay.model.CuentaBancaria;
import cr.ac.ucr.if0009.insecurepay.model.Transaccion;
import cr.ac.ucr.if0009.insecurepay.model.Usuario;
import cr.ac.ucr.if0009.insecurepay.repository.CuentaRepository;
import cr.ac.ucr.if0009.insecurepay.repository.TransaccionRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;

@Service
public class TransaccionService {

    private static final int MAX_TERMINO = 100;
    private static final int MAX_CONCEPTO = 500;

    private final TransaccionRepository transaccionRepository;
    private final CuentaRepository cuentaRepository;
    private final SesionService sesionService;

    public TransaccionService(TransaccionRepository transaccionRepository,
                              CuentaRepository cuentaRepository,
                              SesionService sesionService) {
        this.transaccionRepository = transaccionRepository;
        this.cuentaRepository = cuentaRepository;
        this.sesionService = sesionService;
    }

    /** Un cliente solo ve sus movimientos; ADMIN/AUDITOR ven todos. */
    public List<TransaccionDto> listarVisibles(String authHeader) {
        Usuario usuario = sesionService.usuarioAutenticado(authHeader);
        List<Transaccion> lista = sesionService.esPrivilegiado(usuario)
                ? transaccionRepository.findAllByOrderByFechaDesc()
                : transaccionRepository.findDeUsuario(usuario.getId());
        return lista.stream().map(this::mapearDto).toList();
    }

    public TransaccionDto obtenerPorId(Long id, String authHeader) {
        Usuario usuario = sesionService.usuarioAutenticado(authHeader);
        Transaccion t = transaccionRepository.findById(id)
                .orElseThrow(() -> new RecursoNoEncontradoException("Transaccion no existe."));
        boolean participa = sesionService.esPropietario(usuario, t.getCuentaOrigen())
                || sesionService.esPropietario(usuario, t.getCuentaDestino());
        if (!participa && !sesionService.esPrivilegiado(usuario)) {
            throw new AccesoDenegadoException("Acceso no autorizado a transaccion ajena.");
        }
        return mapearDto(t);
    }

    public List<TransaccionDto> obtenerPorCuenta(Long cuentaId, String authHeader) {
        Usuario usuario = sesionService.usuarioAutenticado(authHeader);
        CuentaBancaria cuenta = cuentaRepository.findById(cuentaId)
                .orElseThrow(() -> new RecursoNoEncontradoException("Cuenta bancaria no existe."));
        if (!sesionService.esPropietario(usuario, cuenta) && !sesionService.esPrivilegiado(usuario)) {
            throw new AccesoDenegadoException("Acceso no autorizado a cuenta ajena.");
        }
        return transaccionRepository.findByCuentaOrigenIdOrCuentaDestinoIdOrderByFechaDesc(cuentaId, cuentaId)
                .stream().map(this::mapearDto).toList();
    }

    // [REMEDIACION 3.1 - A03:2021 SQL Injection / CWE-89]
    // Se elimina createNativeQuery con concatenacion de strings. La busqueda usa JPQL
    // parametrizado: el termino se trata siempre como dato literal, nunca como codigo SQL.
    public List<TransaccionDto> buscarPorTermino(String termino, String authHeader) {
        Usuario usuario = sesionService.usuarioAutenticado(authHeader);
        if (termino == null || termino.trim().isEmpty()) {
            return List.of();
        }
        String limpio = termino.trim();
        if (limpio.length() > MAX_TERMINO) {
            throw new SolicitudInvalidaException("El termino de busqueda excede " + MAX_TERMINO + " caracteres.");
        }
        List<Transaccion> res = sesionService.esPrivilegiado(usuario)
                ? transaccionRepository.buscarPorTerminoSeguro(limpio)
                : transaccionRepository.buscarPorTerminoSeguroDeUsuario(limpio, usuario.getId());
        return res.stream().map(this::mapearDto).toList();
    }

    // [REMEDIACION 3.2 - A01:2021 IDOR en transferencias / CWE-639]
    // [REMEDIACION 3.3 - A03:2021 Stored XSS / CWE-79]
    @Transactional
    public TransaccionDto transferir(TransferenciaDto dto, String authHeader) {
        Usuario usuario = sesionService.usuarioAutenticado(authHeader);

        if (dto == null || dto.getCuentaOrigenId() == null || dto.getNumeroCuentaDestino() == null) {
            throw new SolicitudInvalidaException("Debe indicar la cuenta de origen y la cuenta destino.");
        }
        if (dto.getMonto() == null || dto.getMonto().compareTo(BigDecimal.ZERO) <= 0) {
            throw new SolicitudInvalidaException("El monto a transferir debe ser mayor a cero.");
        }

        CuentaBancaria cuentaOrigen = cuentaRepository.findById(dto.getCuentaOrigenId())
                .orElseThrow(() -> new RecursoNoEncontradoException("Cuenta de origen no existe."));

        // Validar que la cuenta de origen pertenece al usuario autenticado (ni siquiera
        // ADMIN/AUDITOR pueden debitar cuentas ajenas: su privilegio es solo de lectura).
        if (!sesionService.esPropietario(usuario, cuentaOrigen)) {
            throw new AccesoDenegadoException("Fraude detectado: no puede debitar fondos de cuentas ajenas.");
        }

        CuentaBancaria cuentaDestino = cuentaRepository.findByNumeroCuenta(dto.getNumeroCuentaDestino().trim())
                .orElseThrow(() -> new RecursoNoEncontradoException("Cuenta de destino no existe."));

        if (cuentaOrigen.getId().equals(cuentaDestino.getId())) {
            throw new SolicitudInvalidaException("La cuenta destino debe ser distinta de la cuenta de origen.");
        }
        if (cuentaOrigen.getSaldo().compareTo(dto.getMonto()) < 0) {
            throw new SolicitudInvalidaException("Fondos insuficientes en la cuenta de origen.");
        }

        String concepto = dto.getConceptoHtml() == null ? "" : dto.getConceptoHtml().trim();
        if (concepto.length() > MAX_CONCEPTO) {
            throw new SolicitudInvalidaException("El concepto excede " + MAX_CONCEPTO + " caracteres.");
        }

        cuentaOrigen.setSaldo(cuentaOrigen.getSaldo().subtract(dto.getMonto()));
        cuentaDestino.setSaldo(cuentaDestino.getSaldo().add(dto.getMonto()));
        cuentaRepository.save(cuentaOrigen);
        cuentaRepository.save(cuentaDestino);

        Transaccion tx = new Transaccion();
        tx.setCuentaOrigen(cuentaOrigen);
        tx.setCuentaDestino(cuentaDestino);
        tx.setMonto(dto.getMonto());
        // Defensa en profundidad: se codifican los metacaracteres HTML antes de persistir.
        tx.setConceptoHtml(sanitizarTexto(concepto));
        tx.setEstado("COMPLETADA");

        return mapearDto(transaccionRepository.save(tx));
    }

    /** Codificacion de entidades HTML (OWASP XSS Prevention Cheat Sheet, regla #1). */
    static String sanitizarTexto(String entrada) {
        if (entrada == null) return "";
        return entrada
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");
    }

    private TransaccionDto mapearDto(Transaccion t) {
        TransaccionDto dto = new TransaccionDto();
        dto.setId(t.getId());
        dto.setCuentaOrigenId(t.getCuentaOrigen().getId());
        dto.setNumeroCuentaOrigen(t.getCuentaOrigen().getNumeroCuenta());
        dto.setTitularOrigen(t.getCuentaOrigen().getUsuario().getNombreCompleto());
        dto.setCuentaDestinoId(t.getCuentaDestino().getId());
        dto.setNumeroCuentaDestino(t.getCuentaDestino().getNumeroCuenta());
        dto.setTitularDestino(t.getCuentaDestino().getUsuario().getNombreCompleto());
        dto.setMonto(t.getMonto());
        dto.setConceptoHtml(t.getConceptoHtml());
        dto.setFecha(t.getFecha());
        dto.setEstado(t.getEstado());
        return dto;
    }
}

package cr.ac.ucr.if0009.insecurepay.service;

import cr.ac.ucr.if0009.insecurepay.exception.CredencialesInvalidasException;
import cr.ac.ucr.if0009.insecurepay.model.CuentaBancaria;
import cr.ac.ucr.if0009.insecurepay.model.Rol;
import cr.ac.ucr.if0009.insecurepay.model.Usuario;
import cr.ac.ucr.if0009.insecurepay.repository.UsuarioRepository;
import cr.ac.ucr.if0009.insecurepay.util.JwtUtil;
import org.springframework.stereotype.Service;

/**
 * [REMEDIACION 3.2 - A01:2021 Broken Access Control / CWE-639]
 * Resuelve la identidad verificada del solicitante a partir del JWT firmado de la cabecera
 * Authorization. La identidad NUNCA se toma de parametros controlados por el cliente
 * (IDs en la URL o en el cuerpo de la peticion).
 */
@Service
public class SesionService {

    private final JwtUtil jwtUtil;
    private final UsuarioRepository usuarioRepository;

    public SesionService(JwtUtil jwtUtil, UsuarioRepository usuarioRepository) {
        this.jwtUtil = jwtUtil;
        this.usuarioRepository = usuarioRepository;
    }

    public Usuario usuarioAutenticado(String authHeader) {
        String username = jwtUtil.extraerUsername(extraerToken(authHeader));
        // El rol se consulta en BD (fuente de verdad), no se confia en claims adicionales.
        return usuarioRepository.findByUsername(username)
                .orElseThrow(() -> new CredencialesInvalidasException("Token de sesion invalido o expirado."));
    }

    /** ADMIN y AUDITOR pueden consultar (solo lectura) recursos de cualquier cliente. */
    public boolean esPrivilegiado(Usuario usuario) {
        return usuario.getRol() == Rol.ADMIN || usuario.getRol() == Rol.AUDITOR;
    }

    public boolean esPropietario(Usuario usuario, CuentaBancaria cuenta) {
        return cuenta.getUsuario().getId().equals(usuario.getId());
    }

    private String extraerToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ") && authHeader.length() > 7) {
            return authHeader.substring(7).trim();
        }
        throw new CredencialesInvalidasException("Cabecera de autorizacion invalida o ausente.");
    }
}

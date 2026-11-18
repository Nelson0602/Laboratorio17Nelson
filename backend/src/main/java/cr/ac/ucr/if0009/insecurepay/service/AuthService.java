package cr.ac.ucr.if0009.insecurepay.service;

import cr.ac.ucr.if0009.insecurepay.dto.LoginRequest;
import cr.ac.ucr.if0009.insecurepay.dto.LoginResponse;
import cr.ac.ucr.if0009.insecurepay.exception.CredencialesInvalidasException;
import cr.ac.ucr.if0009.insecurepay.model.Usuario;
import cr.ac.ucr.if0009.insecurepay.repository.UsuarioRepository;
import cr.ac.ucr.if0009.insecurepay.util.JwtUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

    private static final String MENSAJE_GENERICO = "Usuario o contrasena incorrectos.";

    private final UsuarioRepository usuarioRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    /**
     * Hash BCrypt de referencia para igualar el tiempo de respuesta cuando el usuario no existe
     * (mitiga la enumeracion de usuarios por canal lateral de tiempo).
     */
    private final String hashSenuelo;

    public AuthService(UsuarioRepository usuarioRepository, JwtUtil jwtUtil, PasswordEncoder passwordEncoder) {
        this.usuarioRepository = usuarioRepository;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
        this.hashSenuelo = passwordEncoder.encode("senuelo-no-valido");
    }

    // [REMEDIACION 4.1 - A02/A07:2021 / CWE-256]
    // La validacion se realiza exclusivamente con passwordEncoder.matches(claveEnviada, hashAlmacenado).
    // Se usa un mensaje de error generico para no revelar si el usuario existe (CWE-204).
    public LoginResponse autenticar(LoginRequest request) {
        if (request == null || request.getUsername() == null || request.getPassword() == null) {
            throw new CredencialesInvalidasException(MENSAJE_GENERICO);
        }

        Optional<Usuario> encontrado = usuarioRepository.findByUsername(request.getUsername());
        String hashAlmacenado = encontrado.map(Usuario::getPassword).orElse(hashSenuelo);
        boolean coincide = passwordEncoder.matches(request.getPassword(), hashAlmacenado);

        if (encontrado.isEmpty() || !coincide) {
            throw new CredencialesInvalidasException(MENSAJE_GENERICO);
        }

        Usuario usuario = encontrado.get();
        String token = jwtUtil.generateToken(usuario.getUsername(), usuario.getRol().name(), usuario.getId());

        // La respuesta nunca incluye la contrasena ni su hash.
        return new LoginResponse(
                token,
                usuario.getUsername(),
                usuario.getNombreCompleto(),
                usuario.getRol().name(),
                usuario.getId()
        );
    }
}

package cr.ac.ucr.if0009.insecurepay.util;

import cr.ac.ucr.if0009.insecurepay.exception.CredencialesInvalidasException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;

/**
 * [REMEDIACION 4.2 - A02:2021 / CWE-798 / CWE-321]
 * La clave HMAC-SHA256 ya no esta quemada en el repositorio: se lee de la variable de
 * entorno JWT_SECRET (propiedad app.jwt.secret). Se exige un minimo de 256 bits (32 bytes).
 * Si la variable no existe, se genera una clave aleatoria efimera con SecureRandom
 * (los tokens dejan de ser validos al reiniciar), nunca una clave predecible.
 */
@Component
public class JwtUtil {

    private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);
    private static final int MIN_KEY_BYTES = 32; // 256 bits para HS256

    @Value("${app.jwt.secret:}")
    private String secret;

    @Value("${app.jwt.expiration-ms:3600000}")
    private long expirationMs;

    private SecretKey signingKey;

    @PostConstruct
    void init() {
        if (secret == null || secret.isBlank()) {
            byte[] random = new byte[64];
            new SecureRandom().nextBytes(random);
            signingKey = Keys.hmacShaKeyFor(random);
            log.warn("JWT_SECRET no definido: se genero una clave aleatoria efimera de 512 bits. "
                    + "Defina la variable de entorno JWT_SECRET (>= 32 bytes) en entornos reales.");
            return;
        }
        byte[] keyBytes = decodificar(secret.trim());
        if (keyBytes.length < MIN_KEY_BYTES) {
            throw new IllegalStateException(
                    "JWT_SECRET debe tener al menos 256 bits (32 bytes). Longitud actual: " + keyBytes.length + " bytes.");
        }
        signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    /** Acepta el secreto en Base64 (recomendado) o, si no es Base64 valido, como texto UTF-8. */
    private static byte[] decodificar(String valor) {
        try {
            return Base64.getDecoder().decode(valor);
        } catch (IllegalArgumentException e) {
            return valor.getBytes(StandardCharsets.UTF_8);
        }
    }

    public String generateToken(String username, String rol, Long usuarioId) {
        return Jwts.builder()
                .subject(username)
                .claim("rol", rol)
                .claim("usuarioId", usuarioId)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(signingKey)
                .compact();
    }

    public Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /** Valida firma y expiracion del token y retorna el username (claim "sub"). */
    public String extraerUsername(String token) {
        try {
            return getClaims(token).getSubject();
        } catch (JwtException | IllegalArgumentException e) {
            throw new CredencialesInvalidasException("Token de sesion invalido o expirado.");
        }
    }

    public boolean validateToken(String token) {
        try {
            getClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}

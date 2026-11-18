package cr.ac.ucr.if0009.insecurepay.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * [REMEDIACION 4.1 - A02:2021 Cryptographic Failures / CWE-256 / CWE-916]
 * Registra BCrypt como funcion de derivacion de contrasenas con factor de trabajo 12
 * (2^12 rondas). El hash incluye sal aleatoria por usuario, lo que impide ataques
 * con tablas arcoiris y hace costosa la fuerza bruta offline.
 */
@Configuration
public class SecurityConfig {

    public static final int BCRYPT_WORK_FACTOR = 12;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(BCRYPT_WORK_FACTOR);
    }
}

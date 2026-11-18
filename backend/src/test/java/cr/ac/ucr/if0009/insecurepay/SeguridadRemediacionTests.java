package cr.ac.ucr.if0009.insecurepay;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import cr.ac.ucr.if0009.insecurepay.model.Usuario;
import cr.ac.ucr.if0009.insecurepay.repository.UsuarioRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Pruebas de regresion que confirman el BLOQUEO DEFENSIVO de los 5 hallazgos del
 * Laboratorio 17. Datos de referencia (data.sql):
 *   carlos_mora (usuario 3) -> cuenta ID 2 | maria_rojas (usuario 4) -> cuenta ID 3
 *   transacciones de carlos: 1, 3, 4 | transaccion ajena a carlos: 2 (maria -> juan)
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class SeguridadRemediacionTests {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired UsuarioRepository usuarioRepository;
    @Autowired PasswordEncoder passwordEncoder;

    private String login(String user, String pass) throws Exception {
        String body = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + user + "\",\"password\":\"" + pass + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return "Bearer " + json.readTree(body).get("token").asText();
    }

    // ---------------- HALLAZGO-01: SQL Injection ----------------

    @Test
    @DisplayName("HALLAZGO-01: el payload de tautologia se trata como literal y no retorna registros")
    void sqlInjectionNeutralizada() throws Exception {
        String carlos = login("carlos_mora", "carlos123");
        for (String payload : new String[]{"' OR 1=1 --", "' OR '1'='1"}) {
            mvc.perform(get("/api/transacciones/buscar").param("termino", payload)
                            .header("Authorization", carlos))
                    .andDo(print())
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$", hasSize(0)));
        }
    }

    @Test
    @DisplayName("HALLAZGO-01: la busqueda legitima funciona y solo retorna transacciones propias")
    void busquedaLegitimaAcotada() throws Exception {
        String carlos = login("carlos_mora", "carlos123");
        mvc.perform(get("/api/transacciones/buscar").param("termino", "COMPLETADA")
                        .header("Authorization", carlos))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(3)))
                .andExpect(jsonPath("$[*].id", not(hasItem(2))));
    }

    // ---------------- HALLAZGO-02: IDOR / BOLA ----------------

    @Test
    @DisplayName("HALLAZGO-02: carlos NO puede ver el saldo de la cuenta de maria (403)")
    void idorSaldoBloqueado() throws Exception {
        String carlos = login("carlos_mora", "carlos123");
        mvc.perform(get("/api/cuentas/3/saldo").header("Authorization", carlos))
                .andDo(print())
                .andExpect(status().isForbidden())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.saldo").doesNotExist());
        mvc.perform(get("/api/cuentas/3").header("Authorization", carlos))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/cuentas/usuario/4").header("Authorization", carlos))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("HALLAZGO-02: el propietario si puede consultar su cuenta (200)")
    void propietarioConsultaSuCuenta() throws Exception {
        String carlos = login("carlos_mora", "carlos123");
        mvc.perform(get("/api/cuentas/2/saldo").header("Authorization", carlos))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cuentaId").value(2));
    }

    @Test
    @DisplayName("HALLAZGO-02: sin token o con token alterado se responde 401")
    void sinTokenNoAutenticado() throws Exception {
        mvc.perform(get("/api/cuentas/2")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/cuentas/2").header("Authorization", "Bearer token.falso.xyz"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("HALLAZGO-02: debitar la cuenta de maria desde la sesion de carlos es rechazado (403) y el saldo no cambia")
    void idorTransferenciaBloqueada() throws Exception {
        String carlos = login("carlos_mora", "carlos123");
        mvc.perform(post("/api/transacciones/transferir").header("Authorization", carlos)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"cuentaOrigenId\":3,\"numeroCuentaDestino\":\"CR05015202001026458901\","
                                + "\"monto\":100000,\"conceptoHtml\":\"prueba\"}"))
                .andDo(print())
                .andExpect(status().isForbidden());

        String maria = login("maria_rojas", "maria123");
        mvc.perform(get("/api/cuentas/3/saldo").header("Authorization", maria))
                .andExpect(jsonPath("$.saldo").value(4850000.00));
    }

    // ---------------- HALLAZGO-03: Stored XSS ----------------

    @Test
    @DisplayName("HALLAZGO-03: el concepto con marcado HTML se persiste codificado (sin etiquetas activas)")
    void xssAlmacenadoCodificado() throws Exception {
        String carlos = login("carlos_mora", "carlos123");
        String concepto = "Pago <img src=x onerror=alert(1)>";
        String body = json.writeValueAsString(java.util.Map.of(
                "cuentaOrigenId", 2,
                "numeroCuentaDestino", "CR05015202001026458902",
                "monto", 1000,
                "conceptoHtml", concepto));
        mvc.perform(post("/api/transacciones/transferir").header("Authorization", carlos)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andDo(print())
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.conceptoHtml", not(containsString("<"))))
                .andExpect(jsonPath("$.conceptoHtml").value("Pago &lt;img src=x onerror=alert(1)&gt;"));
    }

    // ---------------- HALLAZGO-04: Contrasenas en texto plano ----------------

    @Test
    @DisplayName("HALLAZGO-04: las contrasenas en BD son hashes BCrypt con factor >= 10 y el login funciona")
    void contrasenasBcrypt() throws Exception {
        for (Usuario u : usuarioRepository.findAll()) {
            assertThat(u.getPassword()).matches("^\\$2[aby]\\$(1[0-9]|[2-3][0-9])\\$.{53}$");
        }
        Usuario carlos = usuarioRepository.findByUsername("carlos_mora").orElseThrow();
        assertThat(passwordEncoder.matches("carlos123", carlos.getPassword())).isTrue();
        assertThat(carlos.getPassword()).isNotEqualTo("carlos123");

        String resp = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"carlos_mora\",\"password\":\"carlos123\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        JsonNode n = json.readTree(resp);
        assertThat(n.has("password")).isFalse();
        assertThat(resp).doesNotContain("$2a$");
    }

    @Test
    @DisplayName("HALLAZGO-04: credenciales erroneas -> 401 con mensaje generico (sin enumeracion de usuarios)")
    void loginInvalidoGenerico() throws Exception {
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"carlos_mora\",\"password\":\"incorrecta\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Usuario o contrasena incorrectos."));
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"no_existe\",\"password\":\"x\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Usuario o contrasena incorrectos."));
    }

    // ---------------- HALLAZGO-05: Fuga de trazas tecnicas ----------------

    @Test
    @DisplayName("HALLAZGO-05: los errores se responden en RFC 7807 sin stack trace ni detalles internos")
    void erroresSinFugaDeInformacion() throws Exception {
        String carlos = login("carlos_mora", "carlos123");
        String resp = mvc.perform(get("/api/cuentas/abc").header("Authorization", carlos))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.type").exists())
                .andExpect(jsonPath("$.title").exists())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.trace").doesNotExist())
                .andReturn().getResponse().getContentAsString();
        assertThat(resp).doesNotContain("Exception", "at cr.ac.ucr", "SELECT", "org.hibernate");

        String noExiste = mvc.perform(get("/api/cuentas/9999").header("Authorization", carlos))
                .andExpect(status().isNotFound())
                .andReturn().getResponse().getContentAsString();
        assertThat(noExiste).doesNotContain("Exception", "trace", "RecursoNoEncontrado");
    }

    @Test
    @DisplayName("HALLAZGO-05: la consola H2 no esta expuesta")
    void consolaH2Deshabilitada() throws Exception {
        mvc.perform(get("/h2-console")).andExpect(status().isNotFound());
    }
}

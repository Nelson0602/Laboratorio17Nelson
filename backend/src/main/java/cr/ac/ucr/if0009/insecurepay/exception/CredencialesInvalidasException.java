package cr.ac.ucr.if0009.insecurepay.exception;

/**
 * [REMEDIACION] Excepcion de dominio: 401 Unauthorized - credenciales o token invalidos.
 * Es traducida a un ProblemDetail (RFC 7807) por {@link GlobalExceptionHandler}.
 */
public class CredencialesInvalidasException extends RuntimeException {
    public CredencialesInvalidasException(String message) {
        super(message);
    }
}

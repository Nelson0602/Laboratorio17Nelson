package cr.ac.ucr.if0009.insecurepay.exception;

/**
 * [REMEDIACION] Excepcion de dominio: 400 Bad Request - datos de negocio invalidos.
 * Es traducida a un ProblemDetail (RFC 7807) por {@link GlobalExceptionHandler}.
 */
public class SolicitudInvalidaException extends RuntimeException {
    public SolicitudInvalidaException(String message) {
        super(message);
    }
}

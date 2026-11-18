package cr.ac.ucr.if0009.insecurepay.exception;

/**
 * [REMEDIACION] Excepcion de dominio: 404 Not Found - el recurso solicitado no existe.
 * Es traducida a un ProblemDetail (RFC 7807) por {@link GlobalExceptionHandler}.
 */
public class RecursoNoEncontradoException extends RuntimeException {
    public RecursoNoEncontradoException(String message) {
        super(message);
    }
}

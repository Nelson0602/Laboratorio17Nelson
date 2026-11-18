package cr.ac.ucr.if0009.insecurepay.exception;

/**
 * [REMEDIACION] Excepcion de dominio: 403 Forbidden - el usuario autenticado no es propietario del recurso.
 * Es traducida a un ProblemDetail (RFC 7807) por {@link GlobalExceptionHandler}.
 */
public class AccesoDenegadoException extends RuntimeException {
    public AccesoDenegadoException(String message) {
        super(message);
    }
}

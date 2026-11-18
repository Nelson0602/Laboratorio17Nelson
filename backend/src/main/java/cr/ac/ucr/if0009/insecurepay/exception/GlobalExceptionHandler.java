package cr.ac.ucr.if0009.insecurepay.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.net.URI;
import java.time.Instant;
import java.util.UUID;

/**
 * [REMEDIACION 4.2 - CWE-209 / A05:2021]
 * Manejador global que traduce toda excepcion a un ProblemDetail (RFC 7807).
 * Nunca expone stack traces, nombres de clases, sentencias SQL ni mensajes internos:
 * el detalle tecnico solo se registra en el log del servidor junto a un identificador
 * de incidente que el cliente puede reportar a soporte.
 */
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    private static final String TYPE_BASE = "https://insecurepay.ucr.ac.cr/problemas/";

    @ExceptionHandler(AccesoDenegadoException.class)
    public ProblemDetail accesoDenegado(AccesoDenegadoException ex) {
        return problema(HttpStatus.FORBIDDEN, "acceso-denegado", "Acceso denegado", ex.getMessage());
    }

    @ExceptionHandler(RecursoNoEncontradoException.class)
    public ProblemDetail noEncontrado(RecursoNoEncontradoException ex) {
        return problema(HttpStatus.NOT_FOUND, "recurso-no-encontrado", "Recurso no encontrado", ex.getMessage());
    }

    @ExceptionHandler(CredencialesInvalidasException.class)
    public ProblemDetail noAutenticado(CredencialesInvalidasException ex) {
        return problema(HttpStatus.UNAUTHORIZED, "no-autenticado", "Autenticacion requerida", ex.getMessage());
    }

    @ExceptionHandler(SolicitudInvalidaException.class)
    public ProblemDetail solicitudInvalida(SolicitudInvalidaException ex) {
        return problema(HttpStatus.BAD_REQUEST, "solicitud-invalida", "Solicitud invalida", ex.getMessage());
    }

    @ExceptionHandler({
            MissingServletRequestParameterException.class,
            MethodArgumentTypeMismatchException.class,
            HttpMessageNotReadableException.class
    })
    public ProblemDetail entradaMalformada(Exception ex) {
        return problema(HttpStatus.BAD_REQUEST, "solicitud-invalida", "Solicitud invalida",
                "Los parametros enviados no tienen un formato valido.");
    }

    @ExceptionHandler(MissingRequestHeaderException.class)
    public ProblemDetail sinCabecera(MissingRequestHeaderException ex) {
        return problema(HttpStatus.UNAUTHORIZED, "no-autenticado", "Autenticacion requerida",
                "Debe enviar la cabecera Authorization: Bearer <token>.");
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ProblemDetail metodoNoSoportado(HttpRequestMethodNotSupportedException ex) {
        return problema(HttpStatus.METHOD_NOT_ALLOWED, "metodo-no-permitido", "Metodo no permitido",
                "El metodo HTTP no esta soportado para este recurso.");
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ProblemDetail rutaInexistente(NoResourceFoundException ex) {
        return problema(HttpStatus.NOT_FOUND, "recurso-no-encontrado", "Recurso no encontrado",
                "La ruta solicitada no existe.");
    }

    /** Cualquier error no previsto (SQL, NullPointer, etc.) se oculta tras un mensaje generico. */
    @ExceptionHandler(Exception.class)
    public ProblemDetail errorInterno(Exception ex) {
        String incidente = UUID.randomUUID().toString();
        log.error("Error interno no controlado [incidente={}]", incidente, ex);
        ProblemDetail pd = problema(HttpStatus.INTERNAL_SERVER_ERROR, "error-interno", "Error interno del servidor",
                "Ocurrio un error inesperado. Reporte el identificador de incidente a soporte.");
        pd.setProperty("incidente", incidente);
        return pd;
    }

    private ProblemDetail problema(HttpStatus status, String tipo, String titulo, String detalle) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(status, detalle);
        pd.setType(URI.create(TYPE_BASE + tipo));
        pd.setTitle(titulo);
        pd.setProperty("timestamp", Instant.now().toString());
        return pd;
    }
}

package cr.ac.ucr.if0009.insecurepay.repository;

import cr.ac.ucr.if0009.insecurepay.model.Transaccion;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TransaccionRepository extends JpaRepository<Transaccion, Long> {

    List<Transaccion> findByCuentaOrigenIdOrCuentaDestinoIdOrderByFechaDesc(Long cuentaOrigenId, Long cuentaDestinoId);

    // [REMEDIACION 3.1 - A03:2021 SQL Injection / CWE-89]
    // Consulta JPQL declarativa con parametro con nombre (:termino). Hibernate lo envia
    // como bind parameter de un PreparedStatement, por lo que nunca altera la semantica SQL.
    @Query("SELECT t FROM Transaccion t " +
           "WHERE LOWER(t.conceptoHtml) LIKE LOWER(CONCAT('%', :termino, '%')) " +
           "   OR LOWER(t.estado) LIKE LOWER(CONCAT('%', :termino, '%')) " +
           "ORDER BY t.fecha DESC")
    List<Transaccion> buscarPorTerminoSeguro(@Param("termino") String termino);

    // Misma busqueda parametrizada, acotada a las transacciones del usuario autenticado.
    @Query("SELECT t FROM Transaccion t " +
           "WHERE (t.cuentaOrigen.usuario.id = :usuarioId OR t.cuentaDestino.usuario.id = :usuarioId) " +
           "  AND (LOWER(t.conceptoHtml) LIKE LOWER(CONCAT('%', :termino, '%')) " +
           "       OR LOWER(t.estado) LIKE LOWER(CONCAT('%', :termino, '%'))) " +
           "ORDER BY t.fecha DESC")
    List<Transaccion> buscarPorTerminoSeguroDeUsuario(@Param("termino") String termino,
                                                      @Param("usuarioId") Long usuarioId);

    @Query("SELECT t FROM Transaccion t " +
           "WHERE t.cuentaOrigen.usuario.id = :usuarioId OR t.cuentaDestino.usuario.id = :usuarioId " +
           "ORDER BY t.fecha DESC")
    List<Transaccion> findDeUsuario(@Param("usuarioId") Long usuarioId);

    List<Transaccion> findAllByOrderByFechaDesc();
}

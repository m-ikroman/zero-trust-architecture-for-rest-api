package com.ikroman.ztaapi.repository;

import com.ikroman.ztaapi.entity.RequestLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

@Repository
public interface RequestLogRepository extends JpaRepository<RequestLog, Long> {

    /**
     * Hitung jumlah request dalam window waktu tertentu.
     * Digunakan oleh CA Engine untuk sinyal Frekuensi Request (bobot 25).
     */
    @Query("SELECT COUNT(r) FROM RequestLog r WHERE r.username = :username AND r.requestTime >= :since")
    long countByUsernameAndRequestTimeAfter(@Param("username") String username,
                                             @Param("since") LocalDateTime since);
}

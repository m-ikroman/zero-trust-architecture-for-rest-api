package com.ikroman.ztaapi.repository;

import com.ikroman.ztaapi.entity.RevokedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Repository
public interface RevokedTokenRepository extends JpaRepository<RevokedToken, Long> {
    boolean existsByJti(String jti);

    @Modifying
    @Transactional
    @Query("DELETE FROM RevokedToken rt WHERE rt.tokenExpiresAt < :now")
    void deleteExpiredTokens(LocalDateTime now);
}

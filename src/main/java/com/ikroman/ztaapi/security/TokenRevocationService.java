package com.ikroman.ztaapi.security;

import com.ikroman.ztaapi.entity.RevokedToken;
import com.ikroman.ztaapi.repository.RevokedTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Token Revocation Service
 * 
 * Mengelola daftar token yang telah direvokasi (Token Revocation List).
 * Ini adalah mekanisme PRE-CHECK yang berjalan SEBELUM kalkulasi skor risiko.
 * 
 * Sesuai Tabel III.1 (BAB 3):
 * "Token yang terdapat dalam daftar revokasi langsung ditolak (HTTP 401)
 *  sebelum kalkulasi skor dimulai; tidak masuk formula akumulasi."
 * 
 * Digunakan untuk menguji API2:2023 Broken Authentication.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TokenRevocationService {

    private final RevokedTokenRepository revokedTokenRepository;
    private final JwtService jwtService;

    /**
     * Periksa apakah token sudah direvokasi (Pre-check ZTA).
     * Dipanggil di awal JwtAuthenticationFilter, sebelum risk scoring.
     */
    public boolean isTokenRevoked(String token) {
        try {
            String jti = jwtService.extractJti(token);
            return revokedTokenRepository.existsByJti(jti);
        } catch (Exception e) {
            log.warn("Error checking token revocation: {}", e.getMessage());
            return true; // Jika error, anggap token tidak valid
        }
    }

    /**
     * Revokasi token berdasarkan JTI.
     * Dipanggil saat: logout, step-up authentication, aktivitas mencurigakan.
     */
    @Transactional
    public void revokeToken(String token, String reason) {
        try {
            String jti = jwtService.extractJti(token);
            String username = jwtService.extractUsername(token);
            LocalDateTime expiresAt = jwtService.extractExpirationAsLocalDateTime(token);

            if (!revokedTokenRepository.existsByJti(jti)) {
                RevokedToken revokedToken = RevokedToken.builder()
                        .jti(jti)
                        .username(username)
                        .reason(reason)
                        .tokenExpiresAt(expiresAt)
                        .build();
                revokedTokenRepository.save(revokedToken);
                log.info("[ZTA] Token revoked: user={} jti={} reason={}", username, jti, reason);
            }
        } catch (Exception e) {
            log.error("Failed to revoke token: {}", e.getMessage());
        }
    }

    /**
     * Scheduler: bersihkan token yang sudah kadaluarsa dari revocation list.
     * Dijalankan setiap jam untuk menjaga performa database.
     */
    @Scheduled(fixedRate = 3600000)
    @Transactional
    public void cleanupExpiredTokens() {
        revokedTokenRepository.deleteExpiredTokens(LocalDateTime.now());
        log.debug("[ZTA] Expired revoked tokens cleaned up");
    }
}

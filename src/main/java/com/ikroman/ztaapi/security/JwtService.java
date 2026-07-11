package com.ikroman.ztaapi.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.UUID;

/**
 * JWT Service - mengelola pembuatan dan validasi JSON Web Token.
 * 
 * Token menyimpan klaim tambahan untuk mendukung Continuous Authentication:
 * - ip_binding  : IP address saat login (untuk sinyal konsistensi IP, bobot 30)
 * - ua_hash     : hash User-Agent saat login (untuk sinyal konsistensi UA, bobot 25)
 * - jti         : JWT ID unik untuk token revocation pre-check
 * - role        : peran pengguna untuk RBAC (menguji API5:2023 BFLA)
 */
@Service
@Slf4j
public class JwtService {

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expiration-ms}")
    private long jwtExpirationMs;

    private SecretKey getSigningKey() {
        byte[] keyBytes = jwtSecret.getBytes();
        // Pastikan key minimal 256-bit
        byte[] paddedKey = new byte[32];
        System.arraycopy(keyBytes, 0, paddedKey, 0, Math.min(keyBytes.length, 32));
        return Keys.hmacShaKeyFor(paddedKey);
    }

    /**
     * Generate JWT token dengan klaim ZTA.
     * 
     * @param username   username pengguna
     * @param role       peran pengguna (ROLE_USER / ROLE_ADMIN)
     * @param ipAddress  IP address klien saat login
     * @param userAgent  User-Agent header klien saat login
     * @return JWT token string
     */
    public String generateToken(String username, String role, String ipAddress, String userAgent) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + jwtExpirationMs);

        return Jwts.builder()
                .id(UUID.randomUUID().toString())          // jti - untuk revocation
                .subject(username)
                .claim("role", role)
                .claim("ip_binding", ipAddress)            // Sinyal 1: Konsistensi IP (bobot 30)
                .claim("ua_hash", hashUserAgent(userAgent)) // Sinyal 2: Konsistensi UA (bobot 25)
                .issuedAt(now)
                .expiration(expiry)
                .signWith(getSigningKey())
                .compact();
    }

    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    public String extractJti(String token) {
        return parseClaims(token).getId();
    }

    public String extractIpBinding(String token) {
        return parseClaims(token).get("ip_binding", String.class);
    }

    public String extractUaHash(String token) {
        return parseClaims(token).get("ua_hash", String.class);
    }

    public String extractRole(String token) {
        return parseClaims(token).get("role", String.class);
    }

    public Date extractExpiration(String token) {
        return parseClaims(token).getExpiration();
    }

    /**
     * Periksa apakah token mendekati masa kedaluarsa (Sinyal 4: Token Expiry Proximity, bobot 20).
     * Threshold: token dianggap "mendekati kedaluarsa" jika sisa waktu < 20% dari total durasi.
     */
    public boolean isTokenNearExpiry(String token) {
        try {
            Claims claims = parseClaims(token);
            Date expiry = claims.getExpiration();
            Date issued = claims.getIssuedAt();
            long totalDuration = expiry.getTime() - issued.getTime();
            long remaining = expiry.getTime() - System.currentTimeMillis();
            // Trigger jika sisa waktu < 20% dari total durasi token
            return remaining > 0 && remaining < (totalDuration * 0.20);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Konversi expiration Date ke LocalDateTime untuk disimpan di RevokedToken.
     */
    public LocalDateTime extractExpirationAsLocalDateTime(String token) {
        Date expiry = extractExpiration(token);
        return expiry.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
    }

    /**
     * Validasi token: periksa signature dan masa berlaku.
     * Token revocation TIDAK dicek di sini — dilakukan sebagai pre-check terpisah
     * di JwtAuthenticationFilter SEBELUM kalkulasi skor risiko (Tabel III.1).
     */
    public boolean isTokenValid(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Hash User-Agent untuk perbandingan yang konsisten dan hemat memori.
     */
    public String hashUserAgent(String userAgent) {
        if (userAgent == null) return "unknown";
        return String.valueOf(userAgent.hashCode());
    }
}

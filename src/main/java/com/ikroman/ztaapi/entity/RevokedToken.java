package com.ikroman.ztaapi.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Entity Token yang Direvokasi (Token Revocation List / Blacklist).
 * 
 * Mekanisme ini adalah PRE-CHECK di luar formula skor risiko.
 * Token yang terdaftar di sini langsung ditolak (HTTP 401) SEBELUM
 * kalkulasi skor risiko dimulai (Tabel III.1 - BAB 3).
 * 
 * Digunakan untuk menguji API2:2023 Broken Authentication:
 * - Token yang di-logout harus langsung tidak bisa digunakan.
 * - Token step-up lama harus direvokasi saat token baru diterbitkan.
 */
@Entity
@Table(name = "revoked_tokens",
    indexes = {
        @Index(name = "idx_token_jti", columnList = "jti", unique = true)
    })
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RevokedToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * JWT ID (jti) - unique identifier dari setiap token.
     * Lebih efisien daripada menyimpan full token string.
     */
    @Column(nullable = false, unique = true, length = 100)
    private String jti;

    @Column(name = "username", length = 50)
    private String username;

    @Column(name = "revoked_at")
    private LocalDateTime revokedAt;

    /**
     * Alasan revokasi: LOGOUT, STEP_UP_REPLACED, SUSPICIOUS_ACTIVITY, ADMIN_REVOKED
     */
    @Column(name = "reason", length = 50)
    private String reason;

    /**
     * Waktu kedaluarsa token asli - untuk membersihkan entri lama (cleanup scheduler).
     */
    @Column(name = "token_expires_at")
    private LocalDateTime tokenExpiresAt;

    @PrePersist
    protected void onCreate() {
        this.revokedAt = LocalDateTime.now();
    }
}

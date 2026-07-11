package com.ikroman.ztaapi.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit Test: JwtService
 * Memverifikasi pembuatan, validasi, dan ekstraksi klaim token JWT.
 */
@DisplayName("JwtService - Unit Test")
class JwtServiceTest {

    private JwtService jwtService;

    private static final String SECRET = "ZTA-SecretKey-2024-UniversitasSiliwangi-Ikroman-Test";
    private static final long EXPIRATION_MS = 900000L; // 15 menit

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "jwtSecret", SECRET);
        ReflectionTestUtils.setField(jwtService, "jwtExpirationMs", EXPIRATION_MS);
    }

    @Test
    @DisplayName("generateToken: menghasilkan token valid dengan klaim ZTA")
    void generateToken_shouldCreateValidToken() {
        String token = jwtService.generateToken("user1", "ROLE_USER", "127.0.0.1", "Mozilla/5.0");

        assertThat(token).isNotBlank();
        assertThat(jwtService.isTokenValid(token)).isTrue();
    }

    @Test
    @DisplayName("extractUsername: mengembalikan username yang benar")
    void extractUsername_shouldReturnCorrectUsername() {
        String token = jwtService.generateToken("user1", "ROLE_USER", "127.0.0.1", "Mozilla/5.0");
        assertThat(jwtService.extractUsername(token)).isEqualTo("user1");
    }

    @Test
    @DisplayName("extractRole: mengembalikan role yang benar")
    void extractRole_shouldReturnCorrectRole() {
        String token = jwtService.generateToken("admin", "ROLE_ADMIN", "10.0.0.1", "curl/7.0");
        assertThat(jwtService.extractRole(token)).isEqualTo("ROLE_ADMIN");
    }

    @Test
    @DisplayName("extractIpBinding: IP address tersimpan di token (Sinyal 1, bobot 30)")
    void extractIpBinding_shouldReturnBoundIp() {
        String token = jwtService.generateToken("user1", "ROLE_USER", "192.168.1.100", "Mozilla/5.0");
        assertThat(jwtService.extractIpBinding(token)).isEqualTo("192.168.1.100");
    }

    @Test
    @DisplayName("extractUaHash: User-Agent hash tersimpan di token (Sinyal 2, bobot 25)")
    void extractUaHash_shouldReturnHashedUserAgent() {
        String ua = "Mozilla/5.0 (Windows NT 10.0)";
        String token = jwtService.generateToken("user1", "ROLE_USER", "127.0.0.1", ua);
        String expectedHash = jwtService.hashUserAgent(ua);
        assertThat(jwtService.extractUaHash(token)).isEqualTo(expectedHash);
    }

    @Test
    @DisplayName("extractJti: setiap token memiliki JTI unik (untuk revocation)")
    void extractJti_shouldBeUniquePerToken() {
        String token1 = jwtService.generateToken("user1", "ROLE_USER", "127.0.0.1", "UA");
        String token2 = jwtService.generateToken("user1", "ROLE_USER", "127.0.0.1", "UA");
        assertThat(jwtService.extractJti(token1)).isNotEqualTo(jwtService.extractJti(token2));
    }

    @Test
    @DisplayName("isTokenValid: token dengan signature salah dianggap tidak valid")
    void isTokenValid_invalidSignature_shouldReturnFalse() {
        String forgedToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.FORGED_SIGNATURE";
        assertThat(jwtService.isTokenValid(forgedToken)).isFalse();
    }

    @Test
    @DisplayName("isTokenValid: string bukan token dianggap tidak valid")
    void isTokenValid_randomString_shouldReturnFalse() {
        assertThat(jwtService.isTokenValid("bukan-token")).isFalse();
        assertThat(jwtService.isTokenValid("")).isFalse();
    }

    @Test
    @DisplayName("isTokenNearExpiry: token baru belum mendekati kedaluarsa")
    void isTokenNearExpiry_freshToken_shouldReturnFalse() {
        String token = jwtService.generateToken("user1", "ROLE_USER", "127.0.0.1", "UA");
        assertThat(jwtService.isTokenNearExpiry(token)).isFalse();
    }

    @Test
    @DisplayName("hashUserAgent: UA yang sama menghasilkan hash yang sama")
    void hashUserAgent_sameInput_shouldReturnSameHash() {
        String ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
        assertThat(jwtService.hashUserAgent(ua)).isEqualTo(jwtService.hashUserAgent(ua));
    }

    @Test
    @DisplayName("hashUserAgent: UA yang berbeda menghasilkan hash yang berbeda")
    void hashUserAgent_differentInput_shouldReturnDifferentHash() {
        String ua1 = "Mozilla/5.0 (Windows NT 10.0)";
        String ua2 = "curl/7.68.0";
        assertThat(jwtService.hashUserAgent(ua1)).isNotEqualTo(jwtService.hashUserAgent(ua2));
    }
}

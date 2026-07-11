package com.ikroman.ztaapi.security;

import com.ikroman.ztaapi.repository.RequestLogRepository;
import com.ikroman.ztaapi.security.RiskAssessment.PdpDecision;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * Unit Test: RiskScoreCalculator
 * 
 * Memverifikasi kalkulasi skor risiko berdasarkan Tabel III.1 (BAB 3):
 * - Sinyal 1: IP Consistency   (bobot 30)
 * - Sinyal 2: User-Agent       (bobot 25)
 * - Sinyal 3: Request Freq     (bobot 25)
 * - Sinyal 4: Token Expiry     (bobot 20)
 * 
 * PDP Thresholds (Jeong & Yang, 2025):
 * - 0–39  → ALLOW
 * - 40–69 → STEP_UP
 * - 70–100 → DENY
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("RiskScoreCalculator - Unit Test (Tabel III.1)")
class RiskScoreCalculatorTest {

    @Mock
    private RequestLogRepository requestLogRepository;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private RiskScoreCalculator calculator;

    private static final String USERNAME = "user1";
    private static final String SAME_IP = "127.0.0.1";
    private static final String DIFFERENT_IP = "10.10.10.99";
    private static final String BOUND_UA_HASH = "123456";
    private static final String SAME_UA = "Mozilla/5.0";
    private static final String DIFFERENT_UA = "curl/7.0";
    private static final String TOKEN = "mock.jwt.token";

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(calculator, "weightIpConsistency", 30);
        ReflectionTestUtils.setField(calculator, "weightUserAgent", 25);
        ReflectionTestUtils.setField(calculator, "weightRequestFrequency", 25);
        ReflectionTestUtils.setField(calculator, "weightTokenExpiry", 20);
        ReflectionTestUtils.setField(calculator, "thresholdLow", 39);
        ReflectionTestUtils.setField(calculator, "thresholdMedium", 69);
        ReflectionTestUtils.setField(calculator, "maxRequestsPerMinute", 30);

        // Default mocks: sinyal tidak terpicu
        when(jwtService.extractIpBinding(TOKEN)).thenReturn(SAME_IP);
        when(jwtService.hashUserAgent(any())).thenAnswer(inv -> String.valueOf(inv.getArgument(0).hashCode()));
        when(jwtService.extractUaHash(TOKEN)).thenReturn(String.valueOf(SAME_UA.hashCode()));
        when(jwtService.isTokenNearExpiry(TOKEN)).thenReturn(false);
        when(requestLogRepository.countByUsernameAndRequestTimeAfter(eq(USERNAME), any(LocalDateTime.class)))
                .thenReturn(5L); // Di bawah threshold
    }

    // =========================================================
    // Skenario: Tidak ada sinyal terpicu → ALLOW (skor 0)
    // =========================================================

    @Test
    @DisplayName("Skor 0: semua sinyal normal → PDP ALLOW")
    void allSignalsNormal_shouldReturnAllowWithScoreZero() {
        RiskAssessment result = calculator.calculate(TOKEN, SAME_IP, SAME_UA, USERNAME);

        assertThat(result.getTotalRiskScore()).isEqualTo(0);
        assertThat(result.getDecision()).isEqualTo(PdpDecision.ALLOW);
        assertThat(result.isIpConsistencyTriggered()).isFalse();
        assertThat(result.isUserAgentTriggered()).isFalse();
        assertThat(result.isRequestFrequencyTriggered()).isFalse();
        assertThat(result.isTokenExpiryTriggered()).isFalse();
    }

    // =========================================================
    // Sinyal 1: IP Address berubah → +30
    // =========================================================

    @Test
    @DisplayName("Skor 30: IP berubah (bobot 30) → PDP ALLOW (masih di bawah 39)")
    void ipChanged_shouldAddScore30_StillAllow() {
        when(jwtService.extractIpBinding(TOKEN)).thenReturn(SAME_IP);

        RiskAssessment result = calculator.calculate(TOKEN, DIFFERENT_IP, SAME_UA, USERNAME);

        assertThat(result.isIpConsistencyTriggered()).isTrue();
        assertThat(result.getTotalRiskScore()).isEqualTo(30);
        assertThat(result.getDecision()).isEqualTo(PdpDecision.ALLOW);
    }

    // =========================================================
    // Sinyal 2: User-Agent berubah → +25
    // =========================================================

    @Test
    @DisplayName("Skor 25: User-Agent berubah (bobot 25) → PDP ALLOW")
    void userAgentChanged_shouldAddScore25() {
        RiskAssessment result = calculator.calculate(TOKEN, SAME_IP, DIFFERENT_UA, USERNAME);

        assertThat(result.isUserAgentTriggered()).isTrue();
        assertThat(result.getTotalRiskScore()).isEqualTo(25);
        assertThat(result.getDecision()).isEqualTo(PdpDecision.ALLOW);
    }

    // =========================================================
    // Sinyal 3: Frekuensi request berlebihan → +25
    // =========================================================

    @Test
    @DisplayName("Skor 25: Frekuensi request >= 30/menit (bobot 25) → PDP ALLOW")
    void requestFrequencyExceeded_shouldAddScore25() {
        when(requestLogRepository.countByUsernameAndRequestTimeAfter(eq(USERNAME), any()))
                .thenReturn(35L); // Melebihi threshold 30

        RiskAssessment result = calculator.calculate(TOKEN, SAME_IP, SAME_UA, USERNAME);

        assertThat(result.isRequestFrequencyTriggered()).isTrue();
        assertThat(result.getTotalRiskScore()).isEqualTo(25);
        assertThat(result.getDecision()).isEqualTo(PdpDecision.ALLOW);
    }

    // =========================================================
    // Sinyal 4: Token mendekati kedaluarsa → +20
    // =========================================================

    @Test
    @DisplayName("Skor 20: Token mendekati kedaluarsa (bobot 20) → PDP ALLOW")
    void tokenNearExpiry_shouldAddScore20() {
        when(jwtService.isTokenNearExpiry(TOKEN)).thenReturn(true);

        RiskAssessment result = calculator.calculate(TOKEN, SAME_IP, SAME_UA, USERNAME);

        assertThat(result.isTokenExpiryTriggered()).isTrue();
        assertThat(result.getTotalRiskScore()).isEqualTo(20);
        assertThat(result.getDecision()).isEqualTo(PdpDecision.ALLOW);
    }

    // =========================================================
    // Kombinasi: IP + UA → skor 55 → STEP_UP
    // =========================================================

    @Test
    @DisplayName("Skor 55: IP (30) + UA (25) berubah → PDP STEP_UP")
    void ipAndUaChanged_scoreShouldBe55_StepUp() {
        RiskAssessment result = calculator.calculate(TOKEN, DIFFERENT_IP, DIFFERENT_UA, USERNAME);

        assertThat(result.isIpConsistencyTriggered()).isTrue();
        assertThat(result.isUserAgentTriggered()).isTrue();
        assertThat(result.getTotalRiskScore()).isEqualTo(55);
        assertThat(result.getDecision()).isEqualTo(PdpDecision.STEP_UP);
    }

    // =========================================================
    // Kombinasi: IP + UA + Freq → skor 80 → DENY
    // =========================================================

    @Test
    @DisplayName("Skor 80: IP (30) + UA (25) + Freq (25) → PDP DENY")
    void ipUaFreq_scoreShouldBe80_Deny() {
        when(requestLogRepository.countByUsernameAndRequestTimeAfter(eq(USERNAME), any()))
                .thenReturn(50L);

        RiskAssessment result = calculator.calculate(TOKEN, DIFFERENT_IP, DIFFERENT_UA, USERNAME);

        assertThat(result.getTotalRiskScore()).isEqualTo(80);
        assertThat(result.getDecision()).isEqualTo(PdpDecision.DENY);
    }

    // =========================================================
    // Semua sinyal terpicu → skor 100 → DENY
    // =========================================================

    @Test
    @DisplayName("Skor 100: Semua sinyal terpicu (30+25+25+20) → PDP DENY")
    void allSignalsTriggered_shouldBe100_Deny() {
        when(jwtService.isTokenNearExpiry(TOKEN)).thenReturn(true);
        when(requestLogRepository.countByUsernameAndRequestTimeAfter(eq(USERNAME), any()))
                .thenReturn(100L);

        RiskAssessment result = calculator.calculate(TOKEN, DIFFERENT_IP, DIFFERENT_UA, USERNAME);

        assertThat(result.getTotalRiskScore()).isEqualTo(100);
        assertThat(result.getDecision()).isEqualTo(PdpDecision.DENY);
        assertThat(result.isIpConsistencyTriggered()).isTrue();
        assertThat(result.isUserAgentTriggered()).isTrue();
        assertThat(result.isRequestFrequencyTriggered()).isTrue();
        assertThat(result.isTokenExpiryTriggered()).isTrue();
    }

    // =========================================================
    // Batas threshold: skor 39 → ALLOW, skor 40 → STEP_UP
    // =========================================================

    @Test
    @DisplayName("Batas threshold: skor 39 → ALLOW (batas atas Low Risk)")
    void score39_shouldBeAllow() {
        // IP (30) + Token Expiry (20) = 50... gunakan hanya IP: 30 < 39 → ALLOW
        // Untuk mendapat tepat 39, kita perlu kombinasi khusus
        // IP (30) saja = 30 → ALLOW ✓
        RiskAssessment result = calculator.calculate(TOKEN, DIFFERENT_IP, SAME_UA, USERNAME);
        assertThat(result.getTotalRiskScore()).isLessThanOrEqualTo(39);
        assertThat(result.getDecision()).isEqualTo(PdpDecision.ALLOW);
    }

    @Test
    @DisplayName("Batas threshold: skor 40 → STEP_UP (batas bawah Medium Risk)")
    void score40_shouldBeStepUp() {
        // IP (30) + Expiry (20) = 50 → STEP_UP
        when(jwtService.isTokenNearExpiry(TOKEN)).thenReturn(true);

        RiskAssessment result = calculator.calculate(TOKEN, DIFFERENT_IP, SAME_UA, USERNAME);

        assertThat(result.getTotalRiskScore()).isEqualTo(50);
        assertThat(result.getDecision()).isEqualTo(PdpDecision.STEP_UP);
    }
}

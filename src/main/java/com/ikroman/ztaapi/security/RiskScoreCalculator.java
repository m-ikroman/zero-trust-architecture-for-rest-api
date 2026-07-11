package com.ikroman.ztaapi.security;

import com.ikroman.ztaapi.repository.RequestLogRepository;
import com.ikroman.ztaapi.security.RiskAssessment.PdpDecision;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Risk Score Calculator
 * 
 * Mengagregasi sinyal kontekstual dan menghitung dynamic risk score.
 * Implementasi berdasarkan Tabel III.1 (BAB 3) dan framework
 * Trust Score dari Jeong & Yang (2025).
 * 
 * Bobot sinyal:
 * - Konsistensi IP Address  : 30
 * - Konsistensi User-Agent  : 25
 * - Frekuensi Request       : 25
 * - Token Expiry Proximity  : 20
 * Total maksimum            : 100
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RiskScoreCalculator {

    private final RequestLogRepository requestLogRepository;
    private final JwtService jwtService;

    // Bobot sinyal (Jeong & Yang, 2025) - Tabel III.1
    @Value("${app.zta.risk.weight.ip-consistency:30}")
    private int weightIpConsistency;

    @Value("${app.zta.risk.weight.user-agent:25}")
    private int weightUserAgent;

    @Value("${app.zta.risk.weight.request-frequency:25}")
    private int weightRequestFrequency;

    @Value("${app.zta.risk.weight.token-expiry:20}")
    private int weightTokenExpiry;

    // Threshold PDP
    @Value("${app.zta.risk.threshold.low:39}")
    private int thresholdLow;

    @Value("${app.zta.risk.threshold.medium:69}")
    private int thresholdMedium;

    // Rate limit: max request per menit
    @Value("${app.zta.rate-limit.max-requests-per-minute:30}")
    private int maxRequestsPerMinute;

    /**
     * Kalkulasi skor risiko berdasarkan sinyal kontekstual saat ini.
     * Dipanggil oleh Continuous Authentication Engine pada setiap request.
     * 
     * @param token       JWT token dari request saat ini
     * @param currentIp   IP address dari request saat ini
     * @param currentUa   User-Agent dari request saat ini
     * @param username    username dari token
     * @return RiskAssessment berisi skor dan keputusan PDP
     */
    public RiskAssessment calculate(String token, String currentIp,
                                     String currentUa, String username) {
        int totalScore = 0;
        List<String> triggeredSignals = new ArrayList<>();

        // === Sinyal 1: Konsistensi IP Address (bobot 30) ===
        String boundIp = jwtService.extractIpBinding(token);
        boolean ipTriggered = isIpChanged(boundIp, currentIp);
        if (ipTriggered) {
            totalScore += weightIpConsistency;
            triggeredSignals.add("IP_CHANGED(+" + weightIpConsistency + ")");
            log.debug("IP mismatch: bound={}, current={}", boundIp, currentIp);
        }

        // === Sinyal 2: Konsistensi User-Agent (bobot 25) ===
        String boundUaHash = jwtService.extractUaHash(token);
        String currentUaHash = jwtService.hashUserAgent(currentUa);
        boolean uaTriggered = !boundUaHash.equals(currentUaHash);
        if (uaTriggered) {
            totalScore += weightUserAgent;
            triggeredSignals.add("UA_CHANGED(+" + weightUserAgent + ")");
            log.debug("UA mismatch: bound={}, current={}", boundUaHash, currentUaHash);
        }

        // === Sinyal 3: Frekuensi Request (bobot 25) ===
        long requestCount = requestLogRepository.countByUsernameAndRequestTimeAfter(
                username, LocalDateTime.now().minusMinutes(1));
        boolean freqTriggered = requestCount >= maxRequestsPerMinute;
        if (freqTriggered) {
            totalScore += weightRequestFrequency;
            triggeredSignals.add("FREQ_EXCEEDED(+" + weightRequestFrequency + ")[" + requestCount + "req/min]");
            log.debug("Request frequency exceeded: {} requests/min for user {}", requestCount, username);
        }

        // === Sinyal 4: Token Expiry Proximity (bobot 20) ===
        boolean expiryTriggered = jwtService.isTokenNearExpiry(token);
        if (expiryTriggered) {
            totalScore += weightTokenExpiry;
            triggeredSignals.add("NEAR_EXPIRY(+" + weightTokenExpiry + ")");
            log.debug("Token near expiry for user {}", username);
        }

        // === Policy Decision Point (PDP) ===
        PdpDecision decision = evaluatePdp(totalScore);
        String detail = buildDetailMessage(totalScore, decision, triggeredSignals);

        log.info("[ZTA] user={} score={} decision={} signals={}",
                username, totalScore, decision, triggeredSignals);

        return RiskAssessment.builder()
                .ipConsistencyTriggered(ipTriggered)
                .userAgentTriggered(uaTriggered)
                .requestFrequencyTriggered(freqTriggered)
                .tokenExpiryTriggered(expiryTriggered)
                .totalRiskScore(totalScore)
                .decision(decision)
                .detailMessage(detail)
                .build();
    }

    /**
     * Policy Decision Point (PDP) - evaluasi skor risiko.
     * Tabel III.1 (BAB 3): tiga level kebijakan akses.
     */
    private PdpDecision evaluatePdp(int score) {
        if (score <= thresholdLow) {
            return PdpDecision.ALLOW;
        } else if (score <= thresholdMedium) {
            return PdpDecision.STEP_UP;
        } else {
            return PdpDecision.DENY;
        }
    }

    private boolean isIpChanged(String boundIp, String currentIp) {
        if (boundIp == null || currentIp == null) return false;
        // Normalisasi: handle IPv4-mapped IPv6 (::ffff:127.0.0.1 → 127.0.0.1)
        String normalizedBound = normalizeIp(boundIp);
        String normalizedCurrent = normalizeIp(currentIp);
        return !normalizedBound.equals(normalizedCurrent);
    }

    private String normalizeIp(String ip) {
        if (ip != null && ip.startsWith("::ffff:")) {
            return ip.substring(7);
        }
        return ip != null ? ip : "";
    }

    private String buildDetailMessage(int score, PdpDecision decision, List<String> signals) {
        StringBuilder sb = new StringBuilder();
        sb.append("RiskScore=").append(score).append(" Decision=").append(decision);
        if (!signals.isEmpty()) {
            sb.append(" Triggers=").append(String.join(",", signals));
        } else {
            sb.append(" Triggers=NONE");
        }
        return sb.toString();
    }
}

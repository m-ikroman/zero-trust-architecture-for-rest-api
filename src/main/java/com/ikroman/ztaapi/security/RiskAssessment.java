package com.ikroman.ztaapi.security;

import lombok.Builder;
import lombok.Data;

/**
 * Hasil evaluasi sinyal kontekstual oleh Continuous Authentication Engine.
 * Sesuai Tabel III.1 - Sinyal Kontekstual dan Bobot Skor Risiko.
 * 
 * Formula akumulasi skor risiko (Jeong & Yang, 2025):
 * RiskScore = Σ(bobot_sinyal) untuk setiap sinyal yang terpicu
 * 
 * Thresholds PDP (Tabel III.1):
 * - 0–39  : ALLOW   (Low Risk)
 * - 40–69 : STEP_UP (Medium Risk) → minta verifikasi tambahan
 * - 70–100: DENY    (High Risk)   → tolak akses, revokasi sesi
 */
@Data
@Builder
public class RiskAssessment {

    // === Hasil evaluasi per sinyal ===
    private boolean ipConsistencyTriggered;   // bobot 30
    private boolean userAgentTriggered;       // bobot 25
    private boolean requestFrequencyTriggered; // bobot 25
    private boolean tokenExpiryTriggered;     // bobot 20

    // === Total skor risiko (0–100) ===
    private int totalRiskScore;

    // === Keputusan PDP ===
    private PdpDecision decision;

    // === Detail untuk response / logging ===
    private String detailMessage;

    public enum PdpDecision {
        ALLOW,    // Skor 0–39: akses diizinkan
        STEP_UP,  // Skor 40–69: minta verifikasi tambahan
        DENY      // Skor 70–100: tolak akses
    }
}

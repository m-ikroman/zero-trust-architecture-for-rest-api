//package com.ikroman.ztaapi.filter;
//
////import com.fasterxml.jackson.databind.ObjectMapper;
//import com.ikroman.ztaapi.dto.ApiResponse;
//import com.ikroman.ztaapi.entity.RequestLog;
//import com.ikroman.ztaapi.repository.RequestLogRepository;
//import com.ikroman.ztaapi.security.JwtService;
//import com.ikroman.ztaapi.security.RiskAssessment;
//import com.ikroman.ztaapi.security.RiskAssessment.PdpDecision;
//import com.ikroman.ztaapi.security.RiskScoreCalculator;
//import com.ikroman.ztaapi.security.TokenRevocationService;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.MediaType;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//import org.springframework.stereotype.Component;
//import org.springframework.util.StringUtils;
//import org.springframework.web.filter.OncePerRequestFilter;
//import tools.jackson.databind.ObjectMapper;
//
//import java.io.IOException;
//import java.util.List;
//
///**
// * JWT Authentication Filter - Komponen Security Filter Chain
// *
// * Filter ini mengimplementasikan alur pemrosesan request ZTA sesuai Gambar III.2 (BAB 3):
// *
// * Step 1 → Client mengirim HTTP Request
// * Step 2 → Security Filter Chain menerima request
// * Step 3 → JWT Authentication Filter: validasi token, verifikasi signature,
// *           periksa masa berlaku, ekstrak klaim
// * Step 3a → TOKEN REVOCATION PRE-CHECK (di luar formula, hard block)
// * Step 3b → Continuous Authentication Engine: evaluasi 4 sinyal kontekstual
// * Step 4  → Risk Score Calculator: hitung skor dinamis
// * Step 5  → Policy Decision Point (PDP): evaluasi skor → ALLOW/STEP_UP/DENY
// * Step 6  → Jika ALLOW: teruskan ke Resource Server
// * Step 7  → Kembalikan response ke Client
// *
// * MODE OPERASI:
// * - ZTA Mode (aktif): seluruh mekanisme ZTA+CA berjalan
// * - Baseline Mode: hanya validasi JWT konvensional (tanpa CA Engine)
// */
//@Component
//@RequiredArgsConstructor
//@Slf4j
//public class JwtAuthenticationFilter extends OncePerRequestFilter {
//
//    private final JwtService jwtService;
//    private final TokenRevocationService tokenRevocationService;
//    private final RiskScoreCalculator riskScoreCalculator;
//    private final RequestLogRepository requestLogRepository;
//    private final ObjectMapper objectMapper;
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request,
//                                    HttpServletResponse response,
//                                    FilterChain filterChain)
//            throws ServletException, IOException {
//
//        String token = extractTokenFromRequest(request);
//
//        // Tidak ada token: lanjutkan (Spring Security akan handle 401 jika endpoint protected)
//        if (token == null) {
//            filterChain.doFilter(request, response);
//            return;
//        }
//
//        // ====================================================================
//        // STEP 3: JWT Authentication Filter
//        // Validasi token (signature, format, masa berlaku)
//        // ====================================================================
//        if (!jwtService.isTokenValid(token)) {
//            sendErrorResponse(response, HttpStatus.UNAUTHORIZED,
//                    "INVALID_TOKEN", "Token tidak valid atau sudah kedaluarsa");
//            return;
//        }
//
//        String username = jwtService.extractUsername(token);
//        String currentIp = getClientIp(request);
//        String currentUa = request.getHeader("User-Agent");
//
//        // ====================================================================
//        // STEP 3a: TOKEN REVOCATION PRE-CHECK (Tabel III.1 - Hard Block)
//        // Di luar formula skor risiko. Token direvokasi → langsung HTTP 401.
//        // ====================================================================
//        if (tokenRevocationService.isTokenRevoked(token)) {
//            log.warn("[ZTA] REVOKED TOKEN used by user={} ip={}", username, currentIp);
//            saveRequestLog(username, currentIp, request, 0, "DENIED_REVOKED");
//            sendErrorResponse(response, HttpStatus.UNAUTHORIZED,
//                    "TOKEN_REVOKED", "Token telah direvokasi. Silakan login kembali.");
//            return;
//        }
//
//        // ====================================================================
//        // STEP 3b-4-5: Continuous Authentication Engine + Risk Score + PDP
//        // Hanya aktif jika mode ZTA. Baseline API skip ke autentikasi biasa.
//        // ====================================================================
//        boolean ztaMode = isZtaMode(request);
//
//        if (ztaMode) {
//            RiskAssessment assessment = riskScoreCalculator.calculate(
//                    token, currentIp, currentUa, username);
//
//            saveRequestLog(username, currentIp, request,
//                    assessment.getTotalRiskScore(), assessment.getDecision().name());
//
//            if (assessment.getDecision() == PdpDecision.DENY) {
//                // STEP 5 → DENY: tolak akses, revokasi sesi
//                tokenRevocationService.revokeToken(token, "SUSPICIOUS_ACTIVITY");
//                log.warn("[ZTA] ACCESS DENIED: user={} score={} detail={}",
//                        username, assessment.getTotalRiskScore(), assessment.getDetailMessage());
//                sendErrorResponse(response, HttpStatus.FORBIDDEN,
//                        "ACCESS_DENIED",
//                        "Akses ditolak. Aktivitas mencurigakan terdeteksi. " + assessment.getDetailMessage());
//                return;
//            }
//
//            if (assessment.getDecision() == PdpDecision.STEP_UP) {
//                // STEP 5 → STEP_UP: minta verifikasi tambahan
//                log.info("[ZTA] STEP-UP REQUIRED: user={} score={} detail={}",
//                        username, assessment.getTotalRiskScore(), assessment.getDetailMessage());
//                sendErrorResponse(response, HttpStatus.UNAUTHORIZED,
//                        "STEP_UP_REQUIRED",
//                        "Verifikasi tambahan diperlukan. " + assessment.getDetailMessage());
//                return;
//            }
//
//            // STEP 5 → ALLOW: set header info risiko untuk observasi
//            response.setHeader("X-ZTA-Risk-Score", String.valueOf(assessment.getTotalRiskScore()));
//            response.setHeader("X-ZTA-Decision", "ALLOW");
//        } else {
//            // === Baseline Mode: hanya catat log tanpa evaluasi ZTA ===
//            saveRequestLog(username, currentIp, request, 0, "BASELINE_ALLOW");
//        }
//
//        // ====================================================================
//        // STEP 6: Set authentication ke SecurityContext
//        // Izinkan request diteruskan ke Resource Server (Controller)
//        // ====================================================================
//        String role = jwtService.extractRole(token);
//        var authorities = List.of(new SimpleGrantedAuthority(role));
//        var authToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
//        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//        SecurityContextHolder.getContext().setAuthentication(authToken);
//
//        filterChain.doFilter(request, response);
//    }
//
//    /**
//     * Tentukan apakah request ini menggunakan mode ZTA atau Baseline.
//     * Mode ditentukan berdasarkan path prefix:
//     * - /api/secured/** → Secured API (ZTA aktif)
//     * - /api/baseline/** → Baseline API (JWT konvensional saja)
//     */
//    private boolean isZtaMode(HttpServletRequest request) {
//        String path = request.getRequestURI();
//        return path.startsWith("/api/secured/");
//    }
//
//    private String extractTokenFromRequest(HttpServletRequest request) {
//        String bearerToken = request.getHeader("Authorization");
//        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
//            return bearerToken.substring(7);
//        }
//        return null;
//    }
//
//    private String getClientIp(HttpServletRequest request) {
//        String xForwardedFor = request.getHeader("X-Forwarded-For");
//        if (StringUtils.hasText(xForwardedFor)) {
//            return xForwardedFor.split(",")[0].trim();
//        }
//        return request.getRemoteAddr();
//    }
//
//    private void saveRequestLog(String username, String ip,
//                                 HttpServletRequest request,
//                                 int riskScore, String decision) {
//        try {
//            requestLogRepository.save(RequestLog.builder()
//                    .username(username)
//                    .ipAddress(ip)
//                    .endpoint(request.getRequestURI())
//                    .httpMethod(request.getMethod())
//                    .riskScore(riskScore)
//                    .pdpDecision(decision)
//                    .build());
//        } catch (Exception e) {
//            log.warn("Failed to save request log: {}", e.getMessage());
//        }
//    }
//
//    private void sendErrorResponse(HttpServletResponse response,
//                                    HttpStatus status,
//                                    String errorCode,
//                                    String message) throws IOException {
//        response.setStatus(status.value());
//        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//        response.setCharacterEncoding("UTF-8");
//
//        ApiResponse<Void> apiResponse = ApiResponse.<Void>builder()
//                .success(false)
//                .errorCode(errorCode)
//                .message(message)
//                .build();
//
//        response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
//    }
//}

package com.ikroman.ztaapi.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikroman.ztaapi.dto.ApiResponse;
import com.ikroman.ztaapi.entity.RequestLog;
import com.ikroman.ztaapi.repository.RequestLogRepository;
import com.ikroman.ztaapi.security.JwtService;
import com.ikroman.ztaapi.security.RiskAssessment;
import com.ikroman.ztaapi.security.RiskAssessment.PdpDecision;
import com.ikroman.ztaapi.security.RiskScoreCalculator;
import com.ikroman.ztaapi.security.TokenRevocationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT Authentication Filter - Komponen Security Filter Chain
 *
 * Filter ini mengimplementasikan alur pemrosesan request ZTA sesuai Gambar III.2 (BAB 3):
 *
 * Step 1 → Client mengirim HTTP Request
 * Step 2 → Security Filter Chain menerima request
 * Step 3 → JWT Authentication Filter: validasi token, verifikasi signature,
 *           periksa masa berlaku, ekstrak klaim
 * Step 3a → TOKEN REVOCATION PRE-CHECK (di luar formula, hard block)
 * Step 3b → Continuous Authentication Engine: evaluasi 4 sinyal kontekstual
 * Step 4  → Risk Score Calculator: hitung skor dinamis
 * Step 5  → Policy Decision Point (PDP): evaluasi skor → ALLOW/STEP_UP/DENY
 * Step 6  → Jika ALLOW: teruskan ke Resource Server
 * Step 7  → Kembalikan response ke Client
 *
 * MODE OPERASI:
 * - ZTA Mode (aktif): seluruh mekanisme ZTA+CA berjalan
 * - Baseline Mode: hanya validasi JWT konvensional (tanpa CA Engine)
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final TokenRevocationService tokenRevocationService;
    private final RiskScoreCalculator riskScoreCalculator;
    private final RequestLogRepository requestLogRepository;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String token = extractTokenFromRequest(request);

        // Tidak ada token: lanjutkan (Spring Security akan handle 401 jika endpoint protected)
        if (token == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // ====================================================================
        // STEP 3: JWT Authentication Filter
        // Validasi token (signature, format, masa berlaku)
        // ====================================================================
        if (!jwtService.isTokenValid(token)) {
            sendErrorResponse(response, HttpStatus.UNAUTHORIZED,
                    "INVALID_TOKEN", "Token tidak valid atau sudah kedaluarsa");
            return;
        }

        String username = jwtService.extractUsername(token);
        String currentIp = getClientIp(request);
        String currentUa = request.getHeader("User-Agent");

        // ====================================================================
        // Tentukan mode operasi: ZTA (secured) atau Baseline (konvensional)
        // ====================================================================
        boolean ztaMode = isZtaMode(request);

        if (ztaMode) {
            // STEP 3a: TOKEN REVOCATION PRE-CHECK — EKSKLUSIF ZTA (Tabel III.1)
            // Baseline TIDAK memiliki mekanisme ini → token yang di-logout
            // masih bisa dipakai di /api/baseline/** (kelemahan arsitektur konvensional).
            // Ini adalah salah satu perbedaan kunci yang dibuktikan skripsi ini.
            if (tokenRevocationService.isTokenRevoked(token)) {
                log.warn("[ZTA] REVOKED TOKEN blocked: user={} ip={}", username, currentIp);
                saveRequestLog(username, currentIp, request, 0, "DENIED_REVOKED");
                sendErrorResponse(response, HttpStatus.UNAUTHORIZED,
                        "TOKEN_REVOKED", "Token telah direvokasi. Silakan login kembali.");
                return;
            }

            // STEP 3b-4-5: CA Engine + Risk Score Calculator + PDP
            RiskAssessment assessment = riskScoreCalculator.calculate(
                    token, currentIp, currentUa, username);

            saveRequestLog(username, currentIp, request,
                    assessment.getTotalRiskScore(), assessment.getDecision().name());

            if (assessment.getDecision() == PdpDecision.DENY) {
                // STEP 5 → DENY: tolak akses, revokasi sesi
                tokenRevocationService.revokeToken(token, "SUSPICIOUS_ACTIVITY");
                log.warn("[ZTA] ACCESS DENIED: user={} score={} detail={}",
                        username, assessment.getTotalRiskScore(), assessment.getDetailMessage());
                sendErrorResponse(response, HttpStatus.FORBIDDEN,
                        "ACCESS_DENIED",
                        "Akses ditolak. Aktivitas mencurigakan terdeteksi. " + assessment.getDetailMessage());
                return;
            }

            if (assessment.getDecision() == PdpDecision.STEP_UP) {
                // STEP 5 → STEP_UP: minta verifikasi tambahan
                log.info("[ZTA] STEP-UP REQUIRED: user={} score={} detail={}",
                        username, assessment.getTotalRiskScore(), assessment.getDetailMessage());
                sendErrorResponse(response, HttpStatus.UNAUTHORIZED,
                        "STEP_UP_REQUIRED",
                        "Verifikasi tambahan diperlukan. " + assessment.getDetailMessage());
                return;
            }

            // STEP 5 → ALLOW: set header info risiko untuk observasi
            response.setHeader("X-ZTA-Risk-Score", String.valueOf(assessment.getTotalRiskScore()));
            response.setHeader("X-ZTA-Decision", "ALLOW");
        } else {
            // === Baseline Mode: hanya catat log tanpa evaluasi ZTA ===
            saveRequestLog(username, currentIp, request, 0, "BASELINE_ALLOW");
        }

        // ====================================================================
        // STEP 6: Set authentication ke SecurityContext
        // Izinkan request diteruskan ke Resource Server (Controller)
        // ====================================================================
        String role = jwtService.extractRole(token);
        var authorities = List.of(new SimpleGrantedAuthority(role));
        var authToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }

    /**
     * Tentukan apakah request ini menggunakan mode ZTA atau Baseline.
     * Mode ditentukan berdasarkan path prefix:
     * - /api/secured/** → Secured API (ZTA aktif)
     * - /api/baseline/** → Baseline API (JWT konvensional saja)
     */
    private boolean isZtaMode(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/api/secured/");
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private void saveRequestLog(String username, String ip,
                                HttpServletRequest request,
                                int riskScore, String decision) {
        try {
            requestLogRepository.save(RequestLog.builder()
                    .username(username)
                    .ipAddress(ip)
                    .endpoint(request.getRequestURI())
                    .httpMethod(request.getMethod())
                    .riskScore(riskScore)
                    .pdpDecision(decision)
                    .build());
        } catch (Exception e) {
            log.warn("Failed to save request log: {}", e.getMessage());
        }
    }

    private void sendErrorResponse(HttpServletResponse response,
                                   HttpStatus status,
                                   String errorCode,
                                   String message) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        ApiResponse<Void> apiResponse = ApiResponse.<Void>builder()
                .success(false)
                .errorCode(errorCode)
                .message(message)
                .build();

        response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
    }
}


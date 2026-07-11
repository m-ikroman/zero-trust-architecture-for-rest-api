package com.ikroman.ztaapi.controller;

import com.ikroman.ztaapi.dto.ApiResponse;
import com.ikroman.ztaapi.dto.ResourceResponse;
import com.ikroman.ztaapi.entity.RequestLog;
import com.ikroman.ztaapi.entity.RevokedToken;
import com.ikroman.ztaapi.repository.RequestLogRepository;
import com.ikroman.ztaapi.repository.RevokedTokenRepository;
import com.ikroman.ztaapi.service.ResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Admin Controller - Endpoint yang hanya bisa diakses oleh ROLE_ADMIN.
 * 
 * Digunakan untuk menguji API5:2023 Broken Function Level Authorization (BFLA):
 * - Akses dengan token ROLE_USER harus ditolak (HTTP 403)
 * - Akses dengan token ROLE_ADMIN harus diizinkan (HTTP 200)
 * 
 * Tersedia dalam dua mode:
 * - /api/secured/admin/** : dengan ZTA aktif
 * - /api/baseline/admin/** : tanpa ZTA (hanya RBAC)
 */
@RestController
@RequiredArgsConstructor
public class AdminController {

    private final ResourceService resourceService;
    private final RequestLogRepository requestLogRepository;
    private final RevokedTokenRepository revokedTokenRepository;

    // ===== SECURED ADMIN ENDPOINTS (ZTA Aktif) =====

    /**
     * GET semua resource semua pengguna - hanya admin.
     * Pengujian API5:2023 BFLA: akses dengan ROLE_USER harus HTTP 403.
     */
    @GetMapping("/api/secured/admin/resources")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<ResourceResponse>>> getAllResourcesSecured() {
        List<ResourceResponse> resources = resourceService.getAllResources();
        return ResponseEntity.ok(ApiResponse.success(
                "[ZTA-ADMIN] Total resource: " + resources.size(), resources));
    }

    /** GET log request ZTA - untuk monitoring skor risiko */
    @GetMapping("/api/secured/admin/logs")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<RequestLog>>> getRequestLogs() {
        List<RequestLog> logs = requestLogRepository.findAll();
        return ResponseEntity.ok(ApiResponse.success(
                "[ZTA-ADMIN] Total log: " + logs.size(), logs));
    }

    /** GET daftar token yang direvokasi */
    @GetMapping("/api/secured/admin/revoked-tokens")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<RevokedToken>>> getRevokedTokens() {
        List<RevokedToken> tokens = revokedTokenRepository.findAll();
        return ResponseEntity.ok(ApiResponse.success(
                "[ZTA-ADMIN] Total token direvokasi: " + tokens.size(), tokens));
    }

    /** GET statistik sistem ZTA */
    @GetMapping("/api/secured/admin/stats")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getZtaStats() {
        long totalLogs = requestLogRepository.count();
        long revokedCount = revokedTokenRepository.count();

        return ResponseEntity.ok(ApiResponse.success("Statistik ZTA",
                Map.of(
                        "total_requests_logged", totalLogs,
                        "total_revoked_tokens", revokedCount,
                        "mode", "SECURED_ZTA"
                )));
    }

    // ===== BASELINE ADMIN ENDPOINTS (Tanpa ZTA) =====

    @GetMapping("/api/baseline/admin/resources")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<ResourceResponse>>> getAllResourcesBaseline() {
        List<ResourceResponse> resources = resourceService.getAllResources();
        return ResponseEntity.ok(ApiResponse.success(
                "[BASELINE-ADMIN] Total resource: " + resources.size(), resources));
    }

    @GetMapping("/api/baseline/admin/stats")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getBaselineStats() {
        return ResponseEntity.ok(ApiResponse.success("Statistik Baseline",
                Map.of("mode", "BASELINE_CONVENTIONAL_JWT")));
    }
}

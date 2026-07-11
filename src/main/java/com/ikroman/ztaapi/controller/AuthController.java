package com.ikroman.ztaapi.controller;

import com.ikroman.ztaapi.dto.ApiResponse;
import com.ikroman.ztaapi.dto.AuthResponse;
import com.ikroman.ztaapi.dto.LoginRequest;
import com.ikroman.ztaapi.dto.RegisterRequest;
import com.ikroman.ztaapi.entity.User;
import com.ikroman.ztaapi.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Auth Controller - endpoint autentikasi publik.
 * 
 * Endpoint ini tidak memerlukan token (permitAll) dan digunakan untuk:
 * - POST /api/auth/register : Registrasi pengguna baru
 * - POST /api/auth/login    : Login dan mendapatkan JWT
 * - POST /api/auth/logout   : Revokasi token (logout)
 * - POST /api/auth/step-up  : Step-Up Authentication (konfirmasi identitas)
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<Map<String, Object>>> register(
            @Valid @RequestBody RegisterRequest request) {

        User user = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("Registrasi berhasil",
                        Map.of("username", user.getUsername(), "role", user.getRole().name())));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        String ipAddress = getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        AuthResponse authResponse = authService.login(request, ipAddress, userAgent);
        return ResponseEntity.ok(ApiResponse.success("Login berhasil", authResponse));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(HttpServletRequest request) {
        String token = extractToken(request);
        if (token == null) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("MISSING_TOKEN", "Token tidak ditemukan"));
        }
        authService.logout(token);
        return ResponseEntity.ok(ApiResponse.success("Logout berhasil. Token telah direvokasi.", null));
    }

    /**
     * Step-Up Authentication Endpoint
     * Dipanggil klien ketika menerima respons STEP_UP_REQUIRED (HTTP 401).
     * Pengguna harus memverifikasi password untuk mendapatkan token baru.
     */
    @PostMapping("/step-up")
    public ResponseEntity<ApiResponse<AuthResponse>> stepUp(
            @RequestBody Map<String, String> body,
            HttpServletRequest httpRequest) {

        String oldToken = extractToken(httpRequest);
        String password = body.get("password");

        if (oldToken == null || password == null) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("MISSING_PARAMS", "Token dan password diperlukan"));
        }

        String ipAddress = getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        AuthResponse response = authService.stepUpAuthentication(oldToken, password, ipAddress, userAgent);
        return ResponseEntity.ok(ApiResponse.success("Step-up authentication berhasil", response));
    }

    private String extractToken(HttpServletRequest request) {
        String bearer = request.getHeader("Authorization");
        if (StringUtils.hasText(bearer) && bearer.startsWith("Bearer ")) {
            return bearer.substring(7);
        }
        return null;
    }

    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(xff)) return xff.split(",")[0].trim();
        return request.getRemoteAddr();
    }
}

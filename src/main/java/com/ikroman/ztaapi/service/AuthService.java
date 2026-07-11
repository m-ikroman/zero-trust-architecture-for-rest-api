package com.ikroman.ztaapi.service;

import com.ikroman.ztaapi.dto.AuthResponse;
import com.ikroman.ztaapi.dto.LoginRequest;
import com.ikroman.ztaapi.dto.RegisterRequest;
import com.ikroman.ztaapi.entity.User;
import com.ikroman.ztaapi.repository.UserRepository;
import com.ikroman.ztaapi.security.JwtService;
import com.ikroman.ztaapi.security.TokenRevocationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Auth Service - mengelola autentikasi dan registrasi pengguna.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final TokenRevocationService tokenRevocationService;

    @Value("${app.jwt.expiration-ms}")
    private long jwtExpirationMs;

    /**
     * Login: autentikasi pengguna dan terbitkan JWT dengan klaim ZTA.
     * Token menyimpan ip_binding dan ua_hash untuk evaluasi CA Engine.
     */
    @Transactional
    public AuthResponse login(LoginRequest request, String ipAddress, String userAgent) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("Pengguna tidak ditemukan"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Password salah");
        }

        if (!user.getIsActive()) {
            throw new BadCredentialsException("Akun tidak aktif");
        }

        String token = jwtService.generateToken(
                user.getUsername(),
                user.getRole().name(),
                ipAddress,
                userAgent);

        log.info("[AUTH] Login sukses: user={} ip={}", user.getUsername(), ipAddress);

        return AuthResponse.builder()
                .accessToken(token)
                .tokenType("Bearer")
                .expiresIn(jwtExpirationMs / 1000)
                .username(user.getUsername())
                .role(user.getRole().name())
                .message("Login berhasil")
                .build();
    }

    /**
     * Logout: revokasi token aktif pengguna.
     */
    public void logout(String token) {
        tokenRevocationService.revokeToken(token, "LOGOUT");
        log.info("[AUTH] Logout: user={}", jwtService.extractUsername(token));
    }

    /**
     * Registrasi pengguna baru.
     */
    @Transactional
    public User register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("Username sudah digunakan");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email sudah digunakan");
        }

        User.Role role = User.Role.ROLE_USER;
        if ("ROLE_ADMIN".equals(request.getRole())) {
            role = User.Role.ROLE_ADMIN;
        }

        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .email(request.getEmail())
                .role(role)
                .build();

        return userRepository.save(user);
    }

    /**
     * Step-Up Authentication: verifikasi password untuk konfirmasi identitas.
     * Setelah sukses: revokasi token lama, terbitkan token baru dengan skor risiko reset.
     */
    @Transactional
    public AuthResponse stepUpAuthentication(String oldToken, String password,
                                              String ipAddress, String userAgent) {
        String username = jwtService.extractUsername(oldToken);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Pengguna tidak ditemukan"));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("Verifikasi gagal: password salah");
        }

        // Revokasi token lama
        tokenRevocationService.revokeToken(oldToken, "STEP_UP_REPLACED");

        // Terbitkan token baru dengan IP dan UA binding yang diperbarui
        String newToken = jwtService.generateToken(
                user.getUsername(),
                user.getRole().name(),
                ipAddress,
                userAgent);

        log.info("[AUTH] Step-up auth sukses: user={} ip={}", username, ipAddress);

        return AuthResponse.builder()
                .accessToken(newToken)
                .tokenType("Bearer")
                .expiresIn(jwtExpirationMs / 1000)
                .username(user.getUsername())
                .role(user.getRole().name())
                .message("Verifikasi berhasil. Token baru diterbitkan.")
                .build();
    }
}

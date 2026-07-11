package com.ikroman.ztaapi.config;

import com.ikroman.ztaapi.entity.Resource;
import com.ikroman.ztaapi.entity.User;
import com.ikroman.ztaapi.repository.ResourceRepository;
import com.ikroman.ztaapi.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Data Initializer - Seed data untuk pengujian
 * 
 * Membuat akun pengguna dan data resource awal yang dibutuhkan
 * untuk menjalankan semua skenario pengujian OWASP (Tabel III.3).
 * 
 * Akun yang dibuat:
 * - user1 / password123 (ROLE_USER)  → pemilik resource 1, 2, 3
 * - user2 / password123 (ROLE_USER)  → pemilik resource 4, 5
 * - admin / admin123   (ROLE_ADMIN)  → akses penuh
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final ResourceRepository resourceRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        if (userRepository.count() > 0) {
            log.info("[INIT] Data sudah ada, skip inisialisasi");
            return;
        }

        // === Buat pengguna ===
        User user1 = userRepository.save(User.builder()
                .username("user1")
                .password(passwordEncoder.encode("password123"))
                .email("user1@test.com")
                .role(User.Role.ROLE_USER)
                .build());

        User user2 = userRepository.save(User.builder()
                .username("user2")
                .password(passwordEncoder.encode("password123"))
                .email("user2@test.com")
                .role(User.Role.ROLE_USER)
                .build());

        User admin = userRepository.save(User.builder()
                .username("admin")
                .password(passwordEncoder.encode("admin123"))
                .email("admin@test.com")
                .role(User.Role.ROLE_ADMIN)
                .build());

        // === Buat resource untuk pengujian BOLA (API1) ===
        resourceRepository.save(Resource.builder()
                .title("Resource Rahasia User1 #1")
                .content("Konten resource pertama milik user1")
                .sensitiveData("DATA_SENSITIF_USER1_001")
                .owner(user1)
                .build());

        resourceRepository.save(Resource.builder()
                .title("Resource User1 #2")
                .content("Konten resource kedua milik user1")
                .sensitiveData("DATA_SENSITIF_USER1_002")
                .owner(user1)
                .build());

        resourceRepository.save(Resource.builder()
                .title("Resource User1 #3")
                .content("Konten resource ketiga milik user1")
                .sensitiveData("DATA_SENSITIF_USER1_003")
                .owner(user1)
                .build());

        resourceRepository.save(Resource.builder()
                .title("Resource Pribadi User2 #1")
                .content("Konten resource pertama milik user2")
                .sensitiveData("DATA_SENSITIF_USER2_001")
                .owner(user2)
                .build());

        resourceRepository.save(Resource.builder()
                .title("Resource User2 #2")
                .content("Konten resource kedua milik user2")
                .sensitiveData("DATA_SENSITIF_USER2_002")
                .owner(user2)
                .build());

        log.info("=================================================");
        log.info("[INIT] Data pengujian berhasil dibuat:");
        log.info("  Akun: user1 / password123 (ROLE_USER) - ID resource: 1,2,3");
        log.info("  Akun: user2 / password123 (ROLE_USER) - ID resource: 4,5");
        log.info("  Akun: admin / admin123 (ROLE_ADMIN)");
        log.info("  Total resource: 5");
        log.info("=================================================");
        log.info("[ZTA] Skenario pengujian:");
        log.info("  API1 BOLA   : Login user1, akses GET /api/secured/resources/4");
        log.info("  API2 BrkAuth: Gunakan token expired/revoked/palsu");
        log.info("  API3 BOPLA  : PUT /api/secured/resources/1 dengan sensitiveData");
        log.info("  API4 RRC    : Kirim >30 req/menit ke endpoint manapun");
        log.info("  API5 BFLA   : Login user1, akses GET /api/secured/admin/resources");
        log.info("  API8 SecMisc: Scan dengan OWASP ZAP");
        log.info("=================================================");
    }
}

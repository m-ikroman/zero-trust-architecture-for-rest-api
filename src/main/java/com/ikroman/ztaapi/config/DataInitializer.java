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
 * Akun utama (OWASP testing):
 * - user1 / password123  → resource ID 11,2,3
 * - user2 / password123  → resource ID 14,5
 * - admin / admin123     → ROLE_ADMIN
 *
 * Akun skenario skor risiko (tiap akun isolasi sinyal berbeda):
 * - score000 / password123  → Skor 0   : semua sinyal aman
 * - score020 / password123  → Skor 20  : Token Expiry Proximity saja
 * - score025 / password123  → Skor 25  : Frekuensi Request saja (>30 req/min)
 * - score030 / password123  → Skor 30  : IP Address berubah saja
 * - score045 / password123  → Skor 45  : IP(30) + Expiry(20) - tapi digenerate near-expiry
 *                                         ATAU Freq(25) + Expiry(20) = 45
 * - score050 / password123  → Skor 50  : IP(30) + Expiry(20) = 50
 * - score055 / password123  → Skor 55  : IP(30) + UA(25) = 55
 * - score075 / password123  → Skor 75  : IP(30) + UA(25) + Expiry(20) = 75
 * - score080 / password123  → Skor 80  : IP(30) + UA(25) + Freq(25) = 80
 * - score100 / password123  → Skor 100 : IP(30) + UA(25) + Freq(25) + Expiry(20) = 100
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

        // === Akun isolasi untuk pengujian skor risiko ===
        // Setiap akun memiliki resource sendiri agar counter log tidak saling mempengaruhi.
        String[] scoreUsers = {
                "score000", "score020", "score025", "score030", "score045",
                "score050", "score055", "score075", "score080", "score100"
        };
        for (int i = 0; i < scoreUsers.length; i++) {
            User su = userRepository.save(User.builder()
                    .username(scoreUsers[i])
                    .password(passwordEncoder.encode("password123"))
                    .email(scoreUsers[i] + "@test.com")
                    .role(User.Role.ROLE_USER)
                    .build());
            resourceRepository.save(Resource.builder()
                    .title("Resource milik " + scoreUsers[i])
                    .content("Konten pengujian skor " + scoreUsers[i])
                    .sensitiveData("SENSITIVE_" + scoreUsers[i].toUpperCase())
                    .owner(su)
                    .build());
        }

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
        log.info("  Akun utama : user1, user2 (ROLE_USER), admin (ROLE_ADMIN)");
        log.info("  Akun skor  : score000 s/d score100 (10 akun isolasi)");
        log.info("  Total resource: 15");
        log.info("=================================================");
        log.info("[ZTA] Skenario skor risiko (Tabel III.1):");
        log.info("  Skor   0 : score000 - semua sinyal aman             → ALLOW");
        log.info("  Skor  20 : score020 - Token Expiry (+20)            → ALLOW");
        log.info("  Skor  25 : score025 - Freq Request (+25)            → ALLOW");
        log.info("  Skor  30 : score030 - IP Changed (+30)              → ALLOW");
        log.info("  Skor  45 : score045 - Freq(+25) + Expiry(+20)      → STEP_UP");
        log.info("  Skor  50 : score050 - IP(+30) + Expiry(+20)        → STEP_UP");
        log.info("  Skor  55 : score055 - IP(+30) + UA(+25)            → STEP_UP");
        log.info("  Skor  75 : score075 - IP(+30) + UA(+25) + Exp(+20) → DENY");
        log.info("  Skor  80 : score080 - IP(+30) + UA(+25) + Freq(+25)→ DENY");
        log.info("  Skor 100 : score100 - Semua sinyal aktif            → DENY");
        log.info("=================================================");
    }
}

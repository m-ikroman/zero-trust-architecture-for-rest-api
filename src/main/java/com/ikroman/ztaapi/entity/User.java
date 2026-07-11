package com.ikroman.ztaapi.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Entity pengguna sistem ZTA API.
 * Menyimpan data akun termasuk peran (role) untuk otorisasi berbasis peran (RBAC).
 */
@Entity
@Table(name = "users")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 50)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false, unique = true, length = 100)
    private String email;

    /**
     * Peran pengguna: ROLE_USER atau ROLE_ADMIN
     * Digunakan untuk pengujian API5:2023 Broken Function Level Authorization (BFLA)
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Role role;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "is_active")
    private Boolean isActive;

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        if (this.isActive == null) this.isActive = true;
        if (this.role == null) this.role = Role.ROLE_USER;
    }

    public enum Role {
        ROLE_USER, ROLE_ADMIN
    }
}

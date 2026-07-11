package com.ikroman.ztaapi.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Entity Resource (data milik pengguna).
 * 
 * Digunakan untuk menguji:
 * - API1:2023 Broken Object Level Authorization (BOLA): 
 *   setiap resource memiliki owner, akses harus divalidasi per-objek.
 * - API3:2023 Broken Object Property Level Authorization:
 *   field 'sensitiveData' hanya boleh diakses oleh owner/admin.
 */
@Entity
@Table(name = "resources")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Resource {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 200)
    private String title;

    @Column(length = 1000)
    private String content;

    /**
     * Data sensitif - hanya boleh terlihat oleh owner atau admin.
     * Digunakan untuk menguji API3:2023 BOPLA.
     */
    @Column(name = "sensitive_data", length = 500)
    private String sensitiveData;

    /**
     * Pemilik resource - digunakan untuk validasi BOLA (API1:2023).
     * Sistem harus memastikan bahwa userId pada token == ownerId.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
}

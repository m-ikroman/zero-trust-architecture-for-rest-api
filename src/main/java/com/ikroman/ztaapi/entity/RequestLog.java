package com.ikroman.ztaapi.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Entity log request per pengguna.
 * 
 * Digunakan oleh Continuous Authentication Engine untuk menghitung
 * sinyal "Frekuensi Request" (bobot 25) pada Tabel III.1.
 * 
 * Jika request melebihi threshold per menit → skor risiko naik 25 poin.
 * Digunakan untuk menguji API4:2023 Unrestricted Resource Consumption.
 */
@Entity
@Table(name = "request_logs",
    indexes = {
        @Index(name = "idx_req_username_time", columnList = "username,request_time")
    })
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RequestLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 50)
    private String username;

    @Column(name = "request_time")
    private LocalDateTime requestTime;

    @Column(name = "endpoint", length = 200)
    private String endpoint;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "http_method", length = 10)
    private String httpMethod;

    @Column(name = "risk_score")
    private Integer riskScore;

    @Column(name = "pdp_decision", length = 20)
    private String pdpDecision;

    @PrePersist
    protected void onCreate() {
        this.requestTime = LocalDateTime.now();
    }
}

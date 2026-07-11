package com.ikroman.ztaapi.controller;

import com.ikroman.ztaapi.dto.ApiResponse;
import com.ikroman.ztaapi.dto.ResourceRequest;
import com.ikroman.ztaapi.dto.ResourceResponse;
import com.ikroman.ztaapi.service.ResourceService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Baseline Resource Controller - Endpoint dengan autentikasi JWT konvensional
 * 
 * Path: /api/baseline/resources/**
 * 
 * Sesuai BAB 3 (3.1.3): Baseline API menggunakan autentikasi statis berbasis JWT
 * konvensional (hanya validasi pada awal sesi) TANPA mekanisme ZTA dan CA.
 * 
 * Filter tetap memvalidasi JWT, tetapi TIDAK menjalankan:
 * - Continuous Authentication Engine
 * - Risk Score Calculator  
 * - Policy Decision Point
 * 
 * Digunakan sebagai pembanding dalam pengujian performa (Tabel III.4):
 * - Response time baseline vs secured
 * - Throughput baseline vs secured
 * - Error rate baseline vs secured
 */
@RestController
@RequestMapping("/api/baseline/resources")
@RequiredArgsConstructor
public class BaselineResourceController {

    private final ResourceService resourceService;

    @GetMapping
    public ResponseEntity<ApiResponse<List<ResourceResponse>>> getMyResources(Authentication auth) {
        List<ResourceResponse> resources = resourceService.getMyResources(auth.getName());
        return ResponseEntity.ok(ApiResponse.success(
                "[BASELINE] Berhasil mengambil " + resources.size() + " resource", resources));
    }

    /**
     * BOLA tidak dicegah di sini karena tidak ada ZTA layer.
     * Service layer tetap melakukan validasi BOLA sebagai kontrol minimum.
     * Dalam pengujian, ini menunjukkan perbedaan perlindungan antara baseline dan secured.
     */
    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<ResourceResponse>> getResourceById(
            @PathVariable Long id, Authentication auth) {
        boolean isAdmin = hasAdminRole(auth);
        ResourceResponse resource = resourceService.getResourceById(id, auth.getName(), isAdmin);
        return ResponseEntity.ok(ApiResponse.success("[BASELINE] Resource ditemukan", resource));
    }

    @PostMapping
    public ResponseEntity<ApiResponse<ResourceResponse>> createResource(
            @Valid @RequestBody ResourceRequest request, Authentication auth) {
        ResourceResponse resource = resourceService.createResource(request, auth.getName());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("[BASELINE] Resource berhasil dibuat", resource));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<ResourceResponse>> updateResource(
            @PathVariable Long id,
            @Valid @RequestBody ResourceRequest request,
            Authentication auth) {
        boolean isAdmin = hasAdminRole(auth);
        ResourceResponse resource = resourceService.updateResource(id, request, auth.getName(), isAdmin);
        return ResponseEntity.ok(ApiResponse.success("[BASELINE] Resource berhasil diperbarui", resource));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> deleteResource(
            @PathVariable Long id, Authentication auth) {
        boolean isAdmin = hasAdminRole(auth);
        resourceService.deleteResource(id, auth.getName(), isAdmin);
        return ResponseEntity.ok(ApiResponse.success("[BASELINE] Resource berhasil dihapus", null));
    }

    private boolean hasAdminRole(Authentication auth) {
        return auth.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }
}

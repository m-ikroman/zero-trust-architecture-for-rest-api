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
 * Secured Resource Controller - Endpoint dengan ZTA + Continuous Authentication
 * 
 * Path: /api/secured/resources/**
 * 
 * Setiap request melalui JwtAuthenticationFilter dengan ZTA mode aktif:
 * 1. Token revocation pre-check
 * 2. CA Engine: evaluasi 4 sinyal kontekstual
 * 3. Risk Score Calculator: hitung skor dinamis
 * 4. PDP: ALLOW / STEP_UP / DENY
 * 
 * Endpoint ini digunakan untuk menguji:
 * - API1:2023 BOLA: GET /api/secured/resources/{id} (akses resource orang lain)
 * - API3:2023 BOPLA: sensitiveData difilter berdasarkan peran
 * - API4:2023 Unrestricted Resource Consumption: CA Engine rate-limit
 */
@RestController
@RequestMapping("/api/secured/resources")
@RequiredArgsConstructor
public class SecuredResourceController {

    private final ResourceService resourceService;

    /** GET semua resource milik pengguna yang sedang login */
    @GetMapping
    public ResponseEntity<ApiResponse<List<ResourceResponse>>> getMyResources(
            Authentication auth) {
        List<ResourceResponse> resources = resourceService.getMyResources(auth.getName());
        return ResponseEntity.ok(ApiResponse.success(
                "Berhasil mengambil " + resources.size() + " resource", resources));
    }

    /**
     * GET resource berdasarkan ID.
     * Validasi BOLA: hanya owner atau admin yang diizinkan.
     * Pengujian API1:2023: coba akses /api/secured/resources/{id_milik_user_lain}
     */
    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<ResourceResponse>> getResourceById(
            @PathVariable Long id, Authentication auth) {
        boolean isAdmin = hasAdminRole(auth);
        ResourceResponse resource = resourceService.getResourceById(id, auth.getName(), isAdmin);
        return ResponseEntity.ok(ApiResponse.success("Resource ditemukan", resource));
    }

    /** POST buat resource baru */
    @PostMapping
    public ResponseEntity<ApiResponse<ResourceResponse>> createResource(
            @Valid @RequestBody ResourceRequest request, Authentication auth) {
        ResourceResponse resource = resourceService.createResource(request, auth.getName());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("Resource berhasil dibuat", resource));
    }

    /**
     * PUT update resource.
     * Validasi BOLA + API3:2023 BOPLA: sensitiveData hanya bisa diubah admin.
     */
    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<ResourceResponse>> updateResource(
            @PathVariable Long id,
            @Valid @RequestBody ResourceRequest request,
            Authentication auth) {
        boolean isAdmin = hasAdminRole(auth);
        ResourceResponse resource = resourceService.updateResource(id, request, auth.getName(), isAdmin);
        return ResponseEntity.ok(ApiResponse.success("Resource berhasil diperbarui", resource));
    }

    /** DELETE resource */
    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> deleteResource(
            @PathVariable Long id, Authentication auth) {
        boolean isAdmin = hasAdminRole(auth);
        resourceService.deleteResource(id, auth.getName(), isAdmin);
        return ResponseEntity.ok(ApiResponse.success("Resource berhasil dihapus", null));
    }

    private boolean hasAdminRole(Authentication auth) {
        return auth.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }
}

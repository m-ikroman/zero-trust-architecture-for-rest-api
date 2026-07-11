package com.ikroman.ztaapi.service;

import com.ikroman.ztaapi.dto.ResourceRequest;
import com.ikroman.ztaapi.dto.ResourceResponse;
import com.ikroman.ztaapi.entity.Resource;
import com.ikroman.ztaapi.entity.User;
import com.ikroman.ztaapi.repository.ResourceRepository;
import com.ikroman.ztaapi.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Resource Service
 * 
 * Menerapkan validasi Object Level Authorization untuk mencegah:
 * - API1:2023 BOLA: verifikasi owner sebelum mengizinkan akses resource
 * - API3:2023 BOPLA: sensitiveData hanya tampil untuk owner/admin
 */
@Service
@RequiredArgsConstructor
public class ResourceService {

    private final ResourceRepository resourceRepository;
    private final UserRepository userRepository;

    public List<ResourceResponse> getMyResources(String username) {
        User owner = getUser(username);
        return resourceRepository.findByOwner(owner).stream()
                .map(r -> toResponse(r, true)) // owner bisa lihat sensitiveData
                .collect(Collectors.toList());
    }

    /**
     * Mengambil resource berdasarkan ID dengan validasi BOLA.
     * Pengguna biasa hanya bisa mengakses resource miliknya sendiri.
     */
    public ResourceResponse getResourceById(Long id, String username, boolean isAdmin) {
        Resource resource = resourceRepository.findById(id)
                .orElseThrow(() -> new jakarta.persistence.EntityNotFoundException("Resource tidak ditemukan"));

        if (!isAdmin && !resource.getOwner().getUsername().equals(username)) {
            // API1:2023 BOLA: akses ditolak karena bukan owner
            throw new AccessDeniedException("Akses ditolak: resource ini bukan milik Anda");
        }

        return toResponse(resource, isAdmin || resource.getOwner().getUsername().equals(username));
    }

    @Transactional
    public ResourceResponse createResource(ResourceRequest request, String username) {
        User owner = getUser(username);

        Resource resource = Resource.builder()
                .title(request.getTitle())
                .content(request.getContent())
                .sensitiveData(request.getSensitiveData())
                .owner(owner)
                .build();

        return toResponse(resourceRepository.save(resource), true);
    }

    /**
     * Update resource dengan validasi kepemilikan (mencegah BOLA).
     * API3:2023 BOPLA: sensitiveData hanya bisa diubah oleh admin.
     */
    @Transactional
    public ResourceResponse updateResource(Long id, ResourceRequest request,
                                            String username, boolean isAdmin) {
        Resource resource = resourceRepository.findById(id)
                .orElseThrow(() -> new jakarta.persistence.EntityNotFoundException("Resource tidak ditemukan"));

        if (!isAdmin && !resource.getOwner().getUsername().equals(username)) {
            throw new AccessDeniedException("Akses ditolak: resource ini bukan milik Anda");
        }

        resource.setTitle(request.getTitle());
        resource.setContent(request.getContent());

        // API3:2023 BOPLA: hanya admin yang boleh mengubah sensitiveData
        if (isAdmin && request.getSensitiveData() != null) {
            resource.setSensitiveData(request.getSensitiveData());
        }

        return toResponse(resourceRepository.save(resource), true);
    }

    @Transactional
    public void deleteResource(Long id, String username, boolean isAdmin) {
        Resource resource = resourceRepository.findById(id)
                .orElseThrow(() -> new jakarta.persistence.EntityNotFoundException("Resource tidak ditemukan"));

        if (!isAdmin && !resource.getOwner().getUsername().equals(username)) {
            throw new AccessDeniedException("Akses ditolak: resource ini bukan milik Anda");
        }

        resourceRepository.delete(resource);
    }

    // === Admin-only: mengambil semua resource ===
    public List<ResourceResponse> getAllResources() {
        return resourceRepository.findAll().stream()
                .map(r -> toResponse(r, true))
                .collect(Collectors.toList());
    }

    private ResourceResponse toResponse(Resource resource, boolean includeSensitive) {
        return ResourceResponse.builder()
                .id(resource.getId())
                .title(resource.getTitle())
                .content(resource.getContent())
                // API3:2023 BOPLA: sensitiveData hanya tampil jika authorized
                .sensitiveData(includeSensitive ? resource.getSensitiveData() : null)
                .ownerUsername(resource.getOwner().getUsername())
                .createdAt(resource.getCreatedAt())
                .updatedAt(resource.getUpdatedAt())
                .build();
    }

    private User getUser(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Pengguna tidak ditemukan: " + username));
    }
}

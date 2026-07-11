package com.ikroman.ztaapi.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikroman.ztaapi.dto.LoginRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration Test: Skenario Pengujian OWASP API Security Top 10 2023
 * Sesuai Tabel III.3 (BAB 3)
 *
 * Cakupan:
 * - API1:2023 BOLA  : Broken Object Level Authorization
 * - API3:2023 BOPLA : Broken Object Property Level Authorization
 * - API5:2023 BFLA  : Broken Function Level Authorization
 * - API8:2023       : Security Misconfiguration (cek security headers)
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("h2")
@DisplayName("OWASP Security Tests - Tabel III.3")
class OwaSpSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String tokenUser1;
    private String tokenUser2;
    private String tokenAdmin;

    @BeforeEach
    void obtainTokens() throws Exception {
        tokenUser1 = login("user1", "password123");
        tokenUser2 = login("user2", "password123");
        tokenAdmin = login("admin", "admin123");
    }

    // =========================================================
    // API1:2023 BOLA - Broken Object Level Authorization
    // Skenario: akses resource user lain dengan manipulasi ID objek
    // =========================================================

    @Test
    @DisplayName("[API1 BOLA][SECURED] user1 akses resource milik user2 → 403")
    void api1_bola_secured_accessOtherUserResource_shouldReturn403() throws Exception {
        // Resource ID 4 dan 5 milik user2
        mockMvc.perform(get("/api/secured/resources/4")
                        .header("Authorization", "Bearer " + tokenUser1))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("ACCESS_DENIED"));
    }

    @Test
    @DisplayName("[API1 BOLA][SECURED] user1 akses resource miliknya sendiri → 200")
    void api1_bola_secured_accessOwnResource_shouldReturn200() throws Exception {
        // Resource ID 1, 2, 3 milik user1
        mockMvc.perform(get("/api/secured/resources/1")
                        .header("Authorization", "Bearer " + tokenUser1))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    @DisplayName("[API1 BOLA][SECURED] admin akses semua resource → 200")
    void api1_bola_secured_adminAccessAnyResource_shouldReturn200() throws Exception {
        mockMvc.perform(get("/api/secured/resources/4")
                        .header("Authorization", "Bearer " + tokenAdmin))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("[API1 BOLA][BASELINE] user1 akses resource user2 → 403 (validasi tetap ada di service layer)")
    void api1_bola_baseline_accessOtherUserResource_shouldReturn403() throws Exception {
        mockMvc.perform(get("/api/baseline/resources/4")
                        .header("Authorization", "Bearer " + tokenUser1))
                .andExpect(status().isForbidden());
    }

    // =========================================================
    // API3:2023 BOPLA - Broken Object Property Level Authorization
    // Skenario: user biasa mencoba mengubah sensitiveData
    // =========================================================

    @Test
    @DisplayName("[API3 BOPLA][SECURED] user biasa tidak bisa mengubah sensitiveData")
    void api3_bopla_secured_userCannotChangeSensitiveData() throws Exception {
        String body = "{\"title\":\"Updated Title\",\"content\":\"Updated Content\","
                + "\"sensitiveData\":\"INJECTED_VALUE\"}";

        MvcResult result = mockMvc.perform(put("/api/secured/resources/1")
                        .header("Authorization", "Bearer " + tokenUser1)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn();

        String resp = result.getResponse().getContentAsString();
        // sensitiveData seharusnya TIDAK berubah ke nilai yang dikirim user
        assertThat(resp).doesNotContain("INJECTED_VALUE");
    }

    @Test
    @DisplayName("[API3 BOPLA][SECURED] admin bisa mengubah sensitiveData")
    void api3_bopla_secured_adminCanChangeSensitiveData() throws Exception {
        String body = "{\"title\":\"Admin Updated\",\"content\":\"Admin Content\","
                + "\"sensitiveData\":\"ADMIN_SET_VALUE\"}";

        mockMvc.perform(put("/api/secured/resources/1")
                        .header("Authorization", "Bearer " + tokenAdmin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.sensitiveData").value("ADMIN_SET_VALUE"));
    }

    // =========================================================
    // API5:2023 BFLA - Broken Function Level Authorization
    // Skenario: user biasa akses endpoint admin
    // =========================================================

    @Test
    @DisplayName("[API5 BFLA][SECURED] ROLE_USER akses admin endpoint → 403")
    void api5_bfla_secured_regularUserAccessAdminEndpoint_shouldReturn403() throws Exception {
        mockMvc.perform(get("/api/secured/admin/resources")
                        .header("Authorization", "Bearer " + tokenUser1))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("[API5 BFLA][SECURED] ROLE_ADMIN akses admin endpoint → 200")
    void api5_bfla_secured_adminAccessAdminEndpoint_shouldReturn200() throws Exception {
        mockMvc.perform(get("/api/secured/admin/resources")
                        .header("Authorization", "Bearer " + tokenAdmin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    @DisplayName("[API5 BFLA][BASELINE] ROLE_USER akses admin endpoint → 403")
    void api5_bfla_baseline_regularUserAccessAdminEndpoint_shouldReturn403() throws Exception {
        mockMvc.perform(get("/api/baseline/admin/resources")
                        .header("Authorization", "Bearer " + tokenUser1))
                .andExpect(status().isForbidden());
    }

    // =========================================================
    // API8:2023 - Security Misconfiguration
    // Skenario: periksa security headers dan eksposur informasi
    // =========================================================

    @Test
    @DisplayName("[API8 SecMisc] Security headers harus ada pada response")
    void api8_securityHeaders_shouldBePresent() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/secured/resources")
                        .header("Authorization", "Bearer invalid"))
                .andReturn();

        // X-Content-Type-Options: nosniff (mencegah MIME sniffing)
        assertThat(result.getResponse().getHeader("X-Content-Type-Options"))
                .isEqualToIgnoringCase("nosniff");
    }

    @Test
    @DisplayName("[API8 SecMisc] Error response tidak mengekspos stack trace")
    void api8_errorResponse_shouldNotExposeStackTrace() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/secured/resources/99999")
                        .header("Authorization", "Bearer " + tokenUser1))
                .andExpect(status().isNotFound())
                .andReturn();

        String body = result.getResponse().getContentAsString();
        assertThat(body).doesNotContain("at com.ikroman");
        assertThat(body).doesNotContain("java.lang");
        assertThat(body).doesNotContain("Exception");
    }

    @Test
    @DisplayName("[API8 SecMisc] Endpoint tidak terdaftar tidak mengekspos info internal")
    void api8_unknownEndpoint_shouldNotExposeInternalInfo() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/internal/config"))
                .andReturn();

        int status = result.getResponse().getStatus();
        assertThat(status).isIn(401, 403, 404);
        assertThat(status).isNotEqualTo(500);
    }

    // =========================================================
    // Pengujian CRUD lengkap (data untuk baseline performa)
    // =========================================================

    @Test
    @DisplayName("[CRUD][SECURED] POST, GET, PUT, DELETE resource sukses")
    void crud_secured_fullLifecycle() throws Exception {
        // CREATE
        String createBody = "{\"title\":\"Test CRUD\",\"content\":\"Konten test\"}";
        MvcResult createResult = mockMvc.perform(post("/api/secured/resources")
                        .header("Authorization", "Bearer " + tokenUser1)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createBody))
                .andExpect(status().isCreated())
                .andReturn();

        long newId = objectMapper.readTree(createResult.getResponse().getContentAsString())
                .path("data").path("id").asLong();

        // READ
        mockMvc.perform(get("/api/secured/resources/" + newId)
                        .header("Authorization", "Bearer " + tokenUser1))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.title").value("Test CRUD"));

        // UPDATE
        String updateBody = "{\"title\":\"Updated CRUD\",\"content\":\"Konten diperbarui\"}";
        mockMvc.perform(put("/api/secured/resources/" + newId)
                        .header("Authorization", "Bearer " + tokenUser1)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(updateBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.title").value("Updated CRUD"));

        // DELETE
        mockMvc.perform(delete("/api/secured/resources/" + newId)
                        .header("Authorization", "Bearer " + tokenUser1))
                .andExpect(status().isOk());
    }

    // =========================================================
    // Helper
    // =========================================================

    private String login(String username, String password) throws Exception {
        LoginRequest req = new LoginRequest();
        req.setUsername(username);
        req.setPassword(password);

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andReturn();

        return objectMapper.readTree(result.getResponse().getContentAsString())
                .path("data").path("accessToken").asText();
    }
}

package com.ikroman.ztaapi.integration;

import com.ikroman.ztaapi.dto.LoginRequest;
import com.ikroman.ztaapi.dto.RegisterRequest;
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
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration Test: Auth Controller
 * 
 * Menguji alur autentikasi lengkap termasuk:
 * - Registrasi pengguna baru
 * - Login dan penerbitan token JWT
 * - Logout dan revokasi token
 * - Penggunaan token yang sudah direvokasi (API2:2023)
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("h2")
@DisplayName("Auth Integration Test")
class AuthIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("Login dengan kredensial valid → mendapat token JWT")
    void login_validCredentials_shouldReturnToken() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setUsername("user1");
        request.setPassword("password123");

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.data.tokenType").value("Bearer"))
                .andReturn();

        String responseBody = result.getResponse().getContentAsString();
        assertThat(responseBody).contains("accessToken");
    }

    @Test
    @DisplayName("Login dengan password salah → 401")
    void login_wrongPassword_shouldReturn401() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setUsername("user1");
        request.setPassword("wrongpassword");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    @DisplayName("Login dengan username tidak ada → 401 (pesan generik, cegah user enumeration)")
    void login_unknownUser_shouldReturn401Generic() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setUsername("tidakada");
        request.setPassword("apapun");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                // Pesan harus generik, tidak menyebutkan "user tidak ditemukan"
                .andExpect(jsonPath("$.message").value("Kredensial tidak valid"));
    }

    @Test
    @DisplayName("Akses endpoint protected tanpa token → 401/403")
    void accessProtectedEndpoint_noToken_shouldBeRejected() throws Exception {
        mockMvc.perform(get("/api/secured/resources"))
                .andExpect(result ->
                        assertThat(result.getResponse().getStatus()).isIn(401, 403));
    }

    @Test
    @DisplayName("API2: Token yang sudah logout tidak bisa digunakan lagi")
    void afterLogout_revokedToken_shouldReturn401() throws Exception {
        // Step 1: Login untuk mendapat token
        LoginRequest loginReq = new LoginRequest();
        loginReq.setUsername("user2");
        loginReq.setPassword("password123");

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isOk())
                .andReturn();

        String responseBody = loginResult.getResponse().getContentAsString();
        String token = objectMapper.readTree(responseBody)
                .path("data").path("accessToken").asText();
        assertThat(token).isNotBlank();

        // Step 2: Verifikasi token masih valid
        mockMvc.perform(get("/api/secured/resources")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        // Step 3: Logout → revokasi token
        mockMvc.perform(post("/api/auth/logout")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        // Step 4: Token yang sama harus ditolak dengan TOKEN_REVOKED
        mockMvc.perform(get("/api/secured/resources")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("TOKEN_REVOKED"));
    }

    @Test
    @DisplayName("Token dengan signature palsu → 401 INVALID_TOKEN")
    void forgedToken_shouldReturn401() throws Exception {
        mockMvc.perform(get("/api/secured/resources")
                        .header("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.FORGED"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("INVALID_TOKEN"));
    }
}

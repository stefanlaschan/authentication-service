package com.motionary.authservice.service;

import com.motionary.authservice.dto.AuthResponse;
import com.motionary.authservice.dto.LoginRequest;
import com.motionary.authservice.dto.SignupRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

@Slf4j
@Service
public class KeycloakService {
    @Value("${keycloak.url}") private String keycloakUrl;
    @Value("${keycloak.realm}") private String realm;
    @Value("${keycloak.client-id}") private String clientId;
    @Value("${keycloak.admin-username}") private String adminUser;
    @Value("${keycloak.admin-password}") private String adminPass;
    @Value("${keycloak.client-secret:}") private String clientSecret;

    private final RestTemplate rest;

    public KeycloakService(RestTemplate restTemplate) {
        this.rest = restTemplate;
    }

    public void signup(SignupRequest req) {
        String adminToken = obtainAdminAccessToken();
        String usersUrl = keycloakUrl + "/admin/realms/" + realm + "/users";

        Map<String, Object> userPayload = Map.of(
                "username", req.getUsername(),
                "email", req.getEmail(),
                "firstName", req.getFirstName(),
                "lastName", req.getLastName(),
                "enabled", true,
                "emailVerified", true,
                "credentials", List.of(
                        Map.of(
                                "type", "password",
                                "temporary", false,
                                "value", req.getPassword()
                        )
                )
        );

        HttpEntity<Map<String, Object>> createReq = new HttpEntity<>(userPayload, jsonHeadersWithBearer(adminToken));

        try {
            ResponseEntity<Void> createResp = rest.postForEntity(usersUrl, createReq, Void.class);
            if (createResp.getStatusCode() != HttpStatus.CREATED) {
                throw new RuntimeException("Failed to create user: " + createResp.getStatusCode());
            }
            log.info("User created successfully: {}", req.getUsername());
        } catch (HttpClientErrorException e) {
            log.error("Failed to create user: {} - {}", e.getStatusCode(), e.getResponseBodyAsString());
            throw new RuntimeException("Failed to create user: " + e.getMessage());
        }
    }

    public AuthResponse login(LoginRequest req) {
        String tokenUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        log.debug("Attempting login for user: {}", req.getUsername());
        log.debug("Token URL: {}", tokenUrl);
        log.debug("Client ID: {}", clientId);
        log.debug("Realm: {}", realm);

        MultiValueMap<String, String> formData = buildTokenRequestForm(
                "password",
                req.getUsername(),
                req.getPassword()
        );

        HttpEntity<MultiValueMap<String, String>> tokenReq = new HttpEntity<>(
                formData,
                urlEncodedHeaders()
        );

        try {
            ResponseEntity<AuthResponse> res = rest.postForEntity(tokenUrl, tokenReq, AuthResponse.class);
            log.info("Login successful for user: {}", req.getUsername());
            return res.getBody();
        } catch (HttpClientErrorException e) {
            log.error("Login failed for user: {} - Status: {}, Body: {}",
                    req.getUsername(), e.getStatusCode(), e.getResponseBodyAsString());
            throw new RuntimeException("Login failed: Invalid credentials");
        } catch (Exception e) {
            log.error("Unexpected error during login for user: {}", req.getUsername(), e);
            throw new RuntimeException("Login failed: " + e.getMessage());
        }
    }

    public AuthResponse refreshToken(String refreshToken) {
        String tokenUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        MultiValueMap<String, String> formData = buildTokenRequestForm(
                "refresh_token",
                null,
                null
        );
        formData.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> tokenReq = new HttpEntity<>(
                formData,
                urlEncodedHeaders()
        );

        try {
            ResponseEntity<AuthResponse> res = rest.postForEntity(tokenUrl, tokenReq, AuthResponse.class);
            log.debug("Token refreshed successfully");
            return res.getBody();
        } catch (HttpClientErrorException e) {
            log.error("Token refresh failed - Status: {}, Body: {}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            throw new RuntimeException("Token refresh failed");
        }
    }

    public void logout(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            log.warn("Logout called with null or empty refresh token");
            return;
        }

        String logoutUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/logout";

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        form.add("refresh_token", refreshToken);

        // Add client_secret if configured (for confidential clients)
        if (clientSecret != null && !clientSecret.isBlank()) {
            form.add("client_secret", clientSecret);
        }

        HttpEntity<MultiValueMap<String, String>> logoutReq = new HttpEntity<>(form, urlEncodedHeaders());

        try {
            ResponseEntity<Void> resp = rest.postForEntity(logoutUrl, logoutReq, Void.class);
            if (resp.getStatusCode().is2xxSuccessful()) {
                log.info("Logout successful");
            }
        } catch (HttpClientErrorException e) {
            log.error("Logout failed - Status: {}, Body: {}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            throw new RuntimeException("Logout failed: " + e.getMessage());
        }
    }

    private String obtainAdminAccessToken() {
        String tokenUrl = keycloakUrl + "/realms/master/protocol/openid-connect/token";

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", "admin-cli");
        form.add("username", adminUser);
        form.add("password", adminPass);

        HttpEntity<MultiValueMap<String, String>> tokenReq = new HttpEntity<>(form, urlEncodedHeaders());

        try {
            ResponseEntity<Map> resp = rest.postForEntity(tokenUrl, tokenReq, Map.class);
            if (resp.getBody() == null || !resp.getBody().containsKey("access_token")) {
                throw new RuntimeException("Admin token response missing access_token");
            }
            log.debug("Admin token obtained successfully");
            return (String) resp.getBody().get("access_token");
        } catch (HttpClientErrorException e) {
            log.error("Failed to obtain admin token - Status: {}, Body: {}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            throw new RuntimeException("Failed to obtain admin token");
        }
    }

    private MultiValueMap<String, String> buildTokenRequestForm(
            String grantType,
            String username,
            String password) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", grantType);
        form.add("client_id", clientId);

        // Add client_secret if configured (for confidential clients)
        if (clientSecret != null && !clientSecret.isBlank()) {
            form.add("client_secret", clientSecret);
            log.debug("Using client_secret for authentication");
        }

        if (username != null) {
            form.add("username", username);
        }
        if (password != null) {
            form.add("password", password);
        }

        return form;
    }

    private HttpHeaders jsonHeadersWithBearer(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }

    private HttpHeaders urlEncodedHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        return headers;
    }
}
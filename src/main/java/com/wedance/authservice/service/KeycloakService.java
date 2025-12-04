package com.wedance.authservice.service;

import com.wedance.authservice.dto.AuthResponse;
import com.wedance.authservice.dto.LoginRequest;
import com.wedance.authservice.dto.SignupRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Collections;
import java.util.Map;

@Service
public class KeycloakService {
    @Value("${keycloak.url}") private String keycloakUrl;
    @Value("${keycloak.realm}") private String realm;
    @Value("${keycloak.client-id}") private String clientId;
    @Value("${keycloak.admin-username}") private String adminUser;
    @Value("${keycloak.admin-password}") private String adminPass;

    private final RestTemplate rest = new RestTemplate();

    public void signup(SignupRequest req) {
        String adminToken = obtainAdminAccessToken();

        // Create user
        String usersUrl = keycloakUrl + "/admin/realms/" + realm + "/users";
        Map<String,Object> userPayload = Map.of(
            "username", req.getUsername(),
            "enabled", true
        );
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(adminToken);
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Map<String,Object>> createReq = new HttpEntity<>(userPayload, headers);
        ResponseEntity<Void> createResp = rest.postForEntity(usersUrl, createReq, Void.class);
        if (createResp.getStatusCode() != HttpStatus.CREATED) {
            throw new RuntimeException("Failed to create user: " + createResp.getStatusCode());
        }

        // extract id from Location header
        URI location = createResp.getHeaders().getLocation();
        if (location == null) throw new RuntimeException("No Location header from Keycloak user creation");
        String path = location.getPath();
        String id = path.substring(path.lastIndexOf('/') + 1);

        // Set password
        String resetUrl = keycloakUrl + "/admin/realms/" + realm + "/users/" + id + "/reset-password";
        Map<String,Object> pwPayload = Map.of(
            "type", "password",
            "temporary", false,
            "value", req.getPassword()
        );
        HttpEntity<Map<String,Object>> pwReq = new HttpEntity<>(pwPayload, headers);
        rest.put(resetUrl, pwReq);
    }

    public AuthResponse login(LoginRequest req) {
        String tokenUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String,String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", clientId);
        form.add("username", req.getUsername());
        form.add("password", req.getPassword());
        // if client has secret, add form.add("client_secret", "...");

        HttpEntity<MultiValueMap<String,String>> tokenReq = new HttpEntity<>(form, headers);
        ResponseEntity<AuthResponse> resp = rest.postForEntity(tokenUrl, tokenReq, AuthResponse.class);
        if (!resp.getStatusCode().is2xxSuccessful() || resp.getBody() == null) {
            throw new RuntimeException("Login failed: " + resp.getStatusCode());
        }
        return resp.getBody();
    }

    private String obtainAdminAccessToken() {
        String tokenUrl = keycloakUrl + "/realms/master/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String,String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", "admin-cli");
        form.add("username", adminUser);
        form.add("password", adminPass);

        HttpEntity<MultiValueMap<String,String>> tokenReq = new HttpEntity<>(form, headers);
        ResponseEntity<Map> resp = rest.postForEntity(tokenUrl, tokenReq, Map.class);
        if (!resp.getStatusCode().is2xxSuccessful() || resp.getBody() == null) {
            throw new RuntimeException("Failed to obtain admin token");
        }
        return (String) resp.getBody().get("access_token");
    }
}
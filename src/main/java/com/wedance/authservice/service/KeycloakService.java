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

import java.util.List;
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
        ResponseEntity<Void> createResp = rest.postForEntity(usersUrl, createReq, Void.class);
        if (createResp.getStatusCode() != HttpStatus.CREATED) {
            throw new RuntimeException("Failed to create user: " + createResp.getStatusCode());
        }
    }

    public AuthResponse login(LoginRequest req) {
        String tokenUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        HttpEntity<MultiValueMap<String,String>> tokenReq = new HttpEntity<>(
                form("password", clientId, req.getUsername(), req.getPassword()),
                urlEncodedHeaders()
        );
        ResponseEntity<AuthResponse> res = rest.postForEntity(tokenUrl, tokenReq, AuthResponse.class);
        if (!res.getStatusCode().is2xxSuccessful() || res.getBody() == null) {
            throw new RuntimeException("Login failed: " + res.getStatusCode());
        }
        return res.getBody();
    }

    private String obtainAdminAccessToken() {
        String tokenUrl = keycloakUrl + "/realms/master/protocol/openid-connect/token";

        HttpEntity<MultiValueMap<String,String>> tokenReq = new HttpEntity<>(
                form("password", "admin-cli", adminUser, adminPass),
                urlEncodedHeaders()
        );
        ResponseEntity<Map> resp = rest.postForEntity(tokenUrl, tokenReq, Map.class);
        if (!resp.getStatusCode().is2xxSuccessful() || resp.getBody() == null) {
            throw new RuntimeException("Failed to obtain admin token");
        }
        return (String) resp.getBody().get("access_token");
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

    private MultiValueMap<String, String> form(String grantType, String client, String username, String password) {
        MultiValueMap<String,String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", grantType);
        form.add("client_id", client);
        form.add("username", username);
        form.add("password", password);
        return form;
    }
}

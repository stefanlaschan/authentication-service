package com.motionary.authservice.dto;

public class LogoutRequest {
    private String refreshToken;

    public LogoutRequest() {}

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}

package com.example.security_demo;

import java.util.List;

public class LoginResponse {
    private String userName;
    private String jwtToken;
    private List<String> roles;

    public LoginResponse(String username, String jwtToken, List<String> roles) {
        this.userName = username;
        this.jwtToken = jwtToken;
        this.roles = roles;
    }

    public String getJwtToken() {
        return jwtToken;
    }

    public void setJwtToken(String jwtToken) {
        this.jwtToken = jwtToken;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }
}
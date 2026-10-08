package com.example.passwordmanager.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class VaultEntryForm {

    @NotBlank(message = "Website or service is required.")
    @Size(max = 2048, message = "Website must be at most 2048 characters.")
    private String site;

    @NotBlank(message = "Username is required.")
    @Size(max = 254, message = "Username must be at most 254 characters.")
    private String username;

    @NotBlank(message = "Password is required.")
    @Size(max = 2048, message = "Password must be at most 2048 characters.")
    private String password;

    public String getSite() {
        return site;
    }

    public void setSite(String site) {
        this.site = site;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}

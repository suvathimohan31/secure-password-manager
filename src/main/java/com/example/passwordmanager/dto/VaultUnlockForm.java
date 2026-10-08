package com.example.passwordmanager.dto;

import jakarta.validation.constraints.NotBlank;

public class VaultUnlockForm {

    @NotBlank(message = "Enter your master password.")
    private String password;

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}

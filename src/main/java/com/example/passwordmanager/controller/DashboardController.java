package com.example.passwordmanager.controller;

import com.example.passwordmanager.dto.SecurityReport;
import com.example.passwordmanager.security.VaultSession;
import com.example.passwordmanager.security.VaultSession.VaultLockedException;
import com.example.passwordmanager.service.SecurityReportService;
import com.example.passwordmanager.service.VaultService;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardController {

    private final VaultService vaultService;
    private final SecurityReportService securityReportService;

    public DashboardController(VaultService vaultService, SecurityReportService securityReportService) {
        this.vaultService = vaultService;
        this.securityReportService = securityReportService;
    }

    @GetMapping("/dashboard")
    public String dashboard(Authentication authentication, HttpSession session, Model model) {
        model.addAttribute("email", authentication.getName());
        try {
            byte[] key = VaultSession.requireKey(session);
            model.addAttribute("securityReport",
                    securityReportService.analyze(vaultService.list(authentication.getName(), key)));
        } catch (VaultLockedException exception) {
            model.addAttribute("vaultLocked", true);
        }
        return "dashboard";
    }
}

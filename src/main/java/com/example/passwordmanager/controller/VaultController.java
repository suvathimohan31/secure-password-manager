package com.example.passwordmanager.controller;

import com.example.passwordmanager.dto.VaultEntryForm;
import com.example.passwordmanager.dto.VaultUnlockForm;
import com.example.passwordmanager.security.VaultSession;
import com.example.passwordmanager.security.VaultSession.VaultLockedException;
import com.example.passwordmanager.service.SecurityReportService;
import com.example.passwordmanager.service.VaultService;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class VaultController {

    private final VaultService vaultService;
    private final SecurityReportService securityReportService;

    public VaultController(VaultService vaultService, SecurityReportService securityReportService) {
        this.vaultService = vaultService;
        this.securityReportService = securityReportService;
    }

    @GetMapping("/vault/unlock")
    public String unlockForm(Model model, HttpSession session) {
        VaultSession.clearKey(session);
        model.addAttribute("form", new VaultUnlockForm());
        return "vault/unlock";
    }

    @PostMapping("/vault/unlock")
    public String unlock(@Valid @ModelAttribute("form") VaultUnlockForm form,
                         BindingResult bindingResult,
                         Authentication authentication,
                         HttpSession session,
                         Model model) {
        VaultSession.clearKey(session);
        if (bindingResult.hasErrors()) {
            return "vault/unlock";
        }

        try {
            byte[] key = vaultService.unlock(authentication.getName(), form.getPassword().toCharArray());
            VaultSession.storeKey(session, key);
            java.util.Arrays.fill(key, (byte) 0);
            vaultService.recordUnlockSuccess(authentication.getName());
            return "redirect:/vault";
        } catch (VaultService.VaultUnlockException exception) {
            vaultService.recordUnlockFailure(authentication.getName());
            model.addAttribute("unlockFailed", true);
            form.setPassword(null);
            return "vault/unlock";
        }
    }

    @GetMapping("/vault")
    public String list(Authentication authentication, HttpSession session, Model model) {
        byte[] key = requireKeyOrRedirect(session);
        if (key == null) {
            return "redirect:/vault/unlock";
        }
        var entries = vaultService.list(authentication.getName(), key);
        model.addAttribute("entries", entries);
        model.addAttribute("securityReport", securityReportService.analyze(entries));
        return "vault/list";
    }

    @GetMapping("/vault/new")
    public String newEntryForm(Authentication authentication, HttpSession session, Model model) {
        if (!isUnlocked(session)) {
            return "redirect:/vault/unlock";
        }
        model.addAttribute("form", new VaultEntryForm());
        model.addAttribute("action", "/vault");
        model.addAttribute("heading", "Add a credential");
        return "vault/form";
    }

    @PostMapping("/vault")
    public String create(@Valid @ModelAttribute("form") VaultEntryForm form,
                         BindingResult bindingResult,
                         Authentication authentication,
                         HttpSession session,
                         Model model) {
        byte[] key = requireKeyOrRedirect(session);
        if (key == null) {
            return "redirect:/vault/unlock";
        }
        if (bindingResult.hasErrors()) {
            model.addAttribute("action", "/vault");
            model.addAttribute("heading", "Add a credential");
            return "vault/form";
        }
        vaultService.create(authentication.getName(), form, key);
        return "redirect:/vault";
    }

    @GetMapping("/vault/{id}/edit")
    public String editForm(@PathVariable Long id,
                           Authentication authentication,
                           HttpSession session,
                           Model model) {
        byte[] key = requireKeyOrRedirect(session);
        if (key == null) {
            return "redirect:/vault/unlock";
        }
        model.addAttribute("form", vaultService.getForm(authentication.getName(), id, key));
        model.addAttribute("action", "/vault/" + id);
        model.addAttribute("heading", "Edit credential");
        return "vault/form";
    }

    @PostMapping("/vault/{id}")
    public String update(@PathVariable Long id,
                         @Valid @ModelAttribute("form") VaultEntryForm form,
                         BindingResult bindingResult,
                         Authentication authentication,
                         HttpSession session,
                         Model model) {
        byte[] key = requireKeyOrRedirect(session);
        if (key == null) {
            return "redirect:/vault/unlock";
        }
        if (bindingResult.hasErrors()) {
            model.addAttribute("action", "/vault/" + id);
            model.addAttribute("heading", "Edit credential");
            return "vault/form";
        }
        vaultService.update(authentication.getName(), id, form, key);
        return "redirect:/vault";
    }

    @PostMapping("/vault/{id}/delete")
    public String delete(@PathVariable Long id, Authentication authentication,
                         HttpSession session) {
        if (!isUnlocked(session)) {
            return "redirect:/vault/unlock";
        }
        vaultService.delete(authentication.getName(), id);
        return "redirect:/vault";
    }

    @PostMapping("/vault/lock")
    public String lock(HttpSession session) {
        VaultSession.clearKey(session);
        return "redirect:/dashboard";
    }

    private byte[] requireKeyOrRedirect(HttpSession session) {
        try {
            return VaultSession.requireKey(session);
        } catch (VaultLockedException exception) {
            return null;
        }
    }

    private boolean isUnlocked(HttpSession session) {
        try {
            VaultSession.requireKey(session);
            return true;
        } catch (VaultLockedException exception) {
            return false;
        }
    }
}

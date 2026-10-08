package com.example.passwordmanager.controller;

import com.example.passwordmanager.service.AuthService;
import com.example.passwordmanager.dto.RegistrationForm;
import jakarta.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.nio.charset.StandardCharsets;

@Controller
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/")
    public String home() {
        return "redirect:/dashboard";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/register")
    public String registerForm(Model model) {
        model.addAttribute("form", new RegistrationForm());
        return "register";
    }

    @PostMapping("/register")
    public String register(@Valid @ModelAttribute("form") RegistrationForm form,
                           BindingResult bindingResult,
                           RedirectAttributes redirectAttributes) {
        if (!bindingResult.hasFieldErrors("password")
                && form.getPassword() != null
                && form.getPassword().getBytes(StandardCharsets.UTF_8).length > 72) {
            bindingResult.rejectValue("password", "password.tooLong",
                    "Master password must be at most 72 UTF-8 bytes.");
        }
        if (!bindingResult.hasFieldErrors("password")
                && !bindingResult.hasFieldErrors("confirmPassword")
                && form.getPassword() != null
                && !form.getPassword().equals(form.getConfirmPassword())) {
            bindingResult.rejectValue("confirmPassword", "password.mismatch",
                    "The master passwords do not match.");
        }
        if (bindingResult.hasErrors()) {
            return "register";
        }

        try {
            authService.register(form.getEmail(), form.getPassword());
        } catch (AuthService.EmailAlreadyRegisteredException exception) {
            bindingResult.rejectValue("email", "email.taken",
                    "An account with that email already exists.");
            return "register";
        } catch (AuthService.PasswordTooLongException exception) {
            bindingResult.rejectValue("password", "password.tooLong",
                    "Master password must be at most 72 UTF-8 bytes.");
            return "register";
        }

        redirectAttributes.addFlashAttribute("registered", true);
        return "redirect:/login";
    }
}

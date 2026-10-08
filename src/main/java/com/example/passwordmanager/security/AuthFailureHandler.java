package com.example.passwordmanager.security;

import com.example.passwordmanager.service.AuthService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class AuthFailureHandler implements AuthenticationFailureHandler {

    private final AuthService authService;

    public AuthFailureHandler(AuthService authService) {
        this.authService = authService;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        authService.recordLoginFailure(request.getParameter("email"));
        response.sendRedirect("/login?error");
    }
}

package com.example.passwordmanager.security;

import com.example.passwordmanager.model.UserAccount;
import com.example.passwordmanager.repository.UserAccountRepository;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserAccountRepository userRepository;

    public CustomUserDetailsService(UserAccountRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        UserAccount account = userRepository.findByEmail(email.trim().toLowerCase(java.util.Locale.ROOT))
                .orElseThrow(() -> new UsernameNotFoundException("Account not found."));
        boolean accountLocked = account.getLockedUntil() != null
                && account.getLockedUntil().isAfter(LocalDateTime.now());

        return User.withUsername(account.getEmail())
                .password(account.getPasswordHash())
                .authorities("ROLE_USER")
                .accountLocked(accountLocked)
                .build();
    }
}

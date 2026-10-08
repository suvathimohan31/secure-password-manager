package com.example.passwordmanager.security;

import com.example.passwordmanager.model.UserAccount;
import com.example.passwordmanager.repository.UserAccountRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@ActiveProfiles({"test", "prod"})
class OwaspSecurityIntegrationTest {

    private static final String MASTER_PASSWORD = "Test-Only-Master-Password-123!";
    private static final String TEST_PASSWORD = "Vault-Test-Password-123!";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private UserAccountRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private Environment environment;

    @Autowired
    private TestRestTemplate testRestTemplate;

    @LocalServerPort
    private int serverPort;

    @BeforeEach
    void cleanTables() {
        jdbc.update("delete from audit_logs");
        jdbc.update("delete from vault_entries");
        jdbc.update("delete from users");
    }

    @Test
    void sqlInjectionInLoginAndRegistrationIsTreatedAsUntrustedInput() throws Exception {
        String email = newEmail();
        register(email, "not-a-sql-injection-password");

        mvc.perform(post("/login")
                        .param("email", "' OR '1'='1")
                        .param("password", "' OR 1=1 -- ")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?error"));
        mvc.perform(post("/register")
                        .param("email", "inject' OR '1'='1@example.test")
                        .param("password", "password-not-a-sql-query")
                        .param("confirmPassword", "password-not-a-sql-query")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("SQLSyntaxErrorException"))));
        assertEquals(1, userRepository.count());
    }

    @Test
    void sqlLookingVaultValuesAreStoredAsEncryptedData() throws Exception {
        String email = newEmail();
        MockHttpSession session = registerAndLogin(email);
        unlock(email, session);

        String sqlText = "' OR 1=1; SELECT 1; --";
        mvc.perform(post("/vault").session(session).with(csrf())
                        .param("site", sqlText)
                        .param("username", sqlText)
                        .param("password", "SQL-Example-Password-123!"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/vault"));

        mvc.perform(get("/vault").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("&#39; OR 1=1; SELECT 1; --")));
        byte[] ciphertext = jdbc.queryForObject(
                "select encrypted_payload from vault_entries", byte[].class);
        assertNotNull(ciphertext);
        assertFalse(new String(ciphertext, StandardCharsets.UTF_8).contains(sqlText));
    }

    @Test
    void storedAndReflectedXssAreRenderedAsInertText() throws Exception {
        String email = newEmail();
        MockHttpSession session = registerAndLogin(email);
        unlock(email, session);
        String script = "<script>alert('stored-xss')</script>";

        mvc.perform(post("/vault").session(session).with(csrf())
                        .param("site", script)
                        .param("username", "test-user")
                        .param("password", TEST_PASSWORD))
                .andExpect(status().is3xxRedirection());

        mvc.perform(get("/vault").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString(script))))
                .andExpect(content().string(containsString("&lt;script&gt;")));

        mvc.perform(get("/login")
                        .queryParam("error", script)
                        .accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString(script))))
                .andExpect(content().string(not(containsString("stored-xss"))));
    }

    @Test
    void userCannotViewEditOrDeleteAnotherUsersEntry() throws Exception {
        String ownerEmail = newEmail();
        MockHttpSession ownerSession = registerAndLogin(ownerEmail);
        unlock(ownerEmail, ownerSession);
        mvc.perform(post("/vault").session(ownerSession).with(csrf())
                        .param("site", "owner-only.example")
                        .param("username", "owner")
                        .param("password", TEST_PASSWORD))
                .andExpect(status().is3xxRedirection());
        Long entryId = jdbc.queryForObject("select id from vault_entries", Long.class);

        String otherEmail = newEmail();
        MockHttpSession otherSession = registerAndLogin(otherEmail);
        unlock(otherEmail, otherSession);

        mvc.perform(get("/vault/{id}/edit", entryId).session(otherSession))
                .andExpect(status().isNotFound());
        mvc.perform(post("/vault/{id}", entryId).session(otherSession).with(csrf())
                        .param("site", "changed.example")
                        .param("username", "attacker")
                        .param("password", TEST_PASSWORD))
                .andExpect(status().isNotFound());
        mvc.perform(post("/vault/{id}/delete", entryId).session(otherSession).with(csrf()))
                .andExpect(status().isNotFound());

        assertEquals(1, jdbc.queryForObject("select count(*) from vault_entries where id = ?", Integer.class,
                entryId));
    }

    @Test
    void postWithoutCsrfTokenIsRejected() throws Exception {
        String email = newEmail();
        MockHttpSession session = registerAndLogin(email);
        unlock(email, session);

        mvc.perform(post("/vault").session(session)
                        .param("site", "csrf.example")
                        .param("username", "user")
                        .param("password", TEST_PASSWORD))
                .andExpect(status().isForbidden());
        assertEquals(0, jdbc.queryForObject("select count(*) from vault_entries", Integer.class));
    }

    @Test
    void fifthFailedLoginLocksAccountAndRefusesCorrectPassword() throws Exception {
        String email = newEmail();
        register(email, MASTER_PASSWORD);

        for (int attempt = 0; attempt < 5; attempt++) {
            mvc.perform(post("/login").with(csrf())
                            .param("email", email)
                            .param("password", "definitely-wrong"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/login?error"));
        }
        UserAccount lockedAccount = userRepository.findByEmail(email).orElseThrow();
        assertEquals(5, lockedAccount.getFailedLoginAttempts());
        assertNotNull(lockedAccount.getLockedUntil());
        mvc.perform(post("/login").with(csrf())
                        .param("email", email)
                        .param("password", MASTER_PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    void repeatedVaultUnlockFailuresAlsoTriggerAccountLockout() throws Exception {
        String email = newEmail();
        MockHttpSession session = registerAndLogin(email);

        for (int attempt = 0; attempt < 5; attempt++) {
            mvc.perform(post("/vault/unlock").session(session).with(csrf())
                            .param("password", "incorrect-unlock-password"))
                    .andExpect(status().isOk())
                    .andExpect(content().string(containsString("Unable to unlock")));
        }

        UserAccount lockedAccount = userRepository.findByEmail(email).orElseThrow();
        assertEquals(5, lockedAccount.getFailedLoginAttempts());
        assertNotNull(lockedAccount.getLockedUntil());

        mvc.perform(post("/vault/unlock").session(session).with(csrf())
                        .param("password", MASTER_PASSWORD))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Unable to unlock")));
        assertFalse(vaultSessionKeyIsPresent(session));
    }

    @Test
    void logoutInvalidatesHttpSessionAndClearsVaultKey() throws Exception {
        String email = newEmail();
        MockHttpSession session = registerAndLogin(email);
        unlock(email, session);
        byte[] storedKey = VaultSession.requireKey(session);
        assertFalse(Arrays.equals(new byte[32], storedKey));

        mvc.perform(post("/logout").session(session).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?logout"));

        assertArrayEquals(new byte[32], storedKey);
        mvc.perform(get("/dashboard").session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    void sessionTimeoutIsConfiguredToFifteenMinutes() {
        assertEquals(Duration.ofMinutes(15),
                Duration.parse("PT" + environment.getProperty("server.servlet.session.timeout")));
    }

    @Test
    void requiredSecurityHeadersArePresent() throws Exception {
        mvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(header().exists("Content-Security-Policy"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andExpect(header().exists("Permissions-Policy"));
    }

    @Test
    void prodProfileSetsSecureSessionCookieAndCookieFlags() {
        assertEquals("true", environment.getProperty("server.servlet.session.cookie.secure"));
        assertEquals("true", environment.getProperty("server.servlet.session.cookie.http-only"));
        assertEquals("lax", environment.getProperty("server.servlet.session.cookie.same-site"));

        var response = testRestTemplate.getForEntity(
                "http://localhost:" + serverPort + "/login", String.class);
        assertEquals(200, response.getStatusCode().value());
        List<String> setCookies = response.getHeaders().get(HttpHeaders.SET_COOKIE);
        assertNotNull(setCookies);
        String sessionCookie = setCookies.stream()
                .filter(value -> value.startsWith("JSESSIONID="))
                .findFirst()
                .orElseThrow();
        assertTrue(sessionCookie.contains("HttpOnly"));
        assertTrue(sessionCookie.toLowerCase().contains("samesite=lax"));
        assertTrue(sessionCookie.contains("Secure"));
    }

    @Test
    void errorResponsesDoNotExposeStackTraces() throws Exception {
        MockHttpSession session = registerAndLogin(newEmail());
        mvc.perform(get("/vault/not-a-number/edit").session(session)
                        .accept(MediaType.TEXT_HTML))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(not(containsString("at com.example.passwordmanager"))))
                .andExpect(content().string(not(containsString("Exception"))))
                .andExpect(content().string(not(containsString("stacktrace"))));
    }

    @Test
    void databaseStoresBcryptHashAndEncryptedVaultPayloadOnly() throws Exception {
        String email = newEmail();
        register(email, MASTER_PASSWORD);
        UserAccount account = userRepository.findByEmail(email).orElseThrow();

        assertTrue(account.getPasswordHash().startsWith("$2"));
        assertTrue(passwordEncoder.matches(MASTER_PASSWORD, account.getPasswordHash()));
        assertFalse(account.getPasswordHash().equals(MASTER_PASSWORD));
        assertEquals(32, account.getVaultKdfSalt().length);

        MockHttpSession session = login(email, MASTER_PASSWORD);
        unlock(email, session);
        String marker = "unique-vault-secret-" + UUID.randomUUID();
        mvc.perform(post("/vault").session(session).with(csrf())
                        .param("site", marker + ".example")
                        .param("username", marker)
                        .param("password", marker))
                .andExpect(status().is3xxRedirection());

        byte[] encrypted = jdbc.queryForObject(
                "select encrypted_payload from vault_entries where user_id = ?", byte[].class, account.getId());
        assertNotNull(encrypted);
        String encryptedAsText = new String(encrypted, StandardCharsets.UTF_8);
        assertFalse(encryptedAsText.contains(marker));
        assertFalse(encryptedAsText.contains(marker + ".example"));
    }

    private void register(String email, String password) throws Exception {
        mvc.perform(post("/register").with(csrf())
                        .param("email", email)
                        .param("password", password)
                        .param("confirmPassword", password))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));
    }

    private MockHttpSession registerAndLogin(String email) throws Exception {
        register(email, MASTER_PASSWORD);
        return login(email, MASTER_PASSWORD);
    }

    private MockHttpSession login(String email, String password) throws Exception {
        var result = mvc.perform(post("/login").with(csrf())
                        .param("email", email)
                        .param("password", password))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/dashboard"))
                .andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }

    private void unlock(String email, MockHttpSession session) throws Exception {
        mvc.perform(post("/vault/unlock").session(session).with(csrf())
                        .param("password", MASTER_PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/vault"));
    }

    private String newEmail() {
        return UUID.randomUUID() + "@example.test";
    }

    private boolean vaultSessionKeyIsPresent(MockHttpSession session) {
        try {
            VaultSession.requireKey(session);
            return true;
        } catch (VaultSession.VaultLockedException exception) {
            return false;
        }
    }
}

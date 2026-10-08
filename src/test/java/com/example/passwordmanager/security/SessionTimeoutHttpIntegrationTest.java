package com.example.passwordmanager.security;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;

import java.io.IOException;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "server.servlet.session.timeout=1m",
        "server.servlet.session.cookie.secure=false",
        "spring.datasource.url=jdbc:h2:mem:session-timeout;DB_CLOSE_DELAY=-1;MODE=MySQL"
})
@ActiveProfiles("test")
class SessionTimeoutHttpIntegrationTest {

    private static final Pattern CSRF_INPUT = Pattern.compile(
            "<input\\b(?=[^>]*\\bname=\"_csrf\")(?=[^>]*\\bvalue=\"([^\"]+)\")[^>]*>");
    private static final String PASSWORD = "Session-Test-Only-2026!";

    @LocalServerPort
    private int serverPort;

    @Test
    void authenticatedSessionExpiresOnRealHttpRequestAfterInactivity() throws Exception {
        CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        HttpClient client = HttpClient.newBuilder()
                .cookieHandler(cookies)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        String baseUrl = "http://localhost:" + serverPort;
        String email = "timeout-" + UUID.randomUUID() + "@example.test";

        HttpResponse<String> registerPage = get(client, baseUrl + "/register");
        postForm(client, baseUrl + "/register", form(
                "email", email,
                "password", PASSWORD,
                "confirmPassword", PASSWORD,
                "_csrf", csrfToken(registerPage.body())));

        HttpResponse<String> loginPage = get(client, baseUrl + "/login");
        HttpResponse<String> dashboard = postForm(client, baseUrl + "/login", form(
                "email", email,
                "password", PASSWORD,
                "_csrf", csrfToken(loginPage.body())));
        assertEquals("/dashboard", dashboard.uri().getPath());
        assertEquals(200, dashboard.statusCode());
        assertTrue(cookies.getCookieStore().getCookies().stream()
                .anyMatch(cookie -> cookie.getName().equals("JSESSIONID")));

        Thread.sleep(Duration.ofSeconds(65).toMillis());

        HttpResponse<String> afterTimeout = get(client, baseUrl + "/dashboard");
        assertEquals("/login", afterTimeout.uri().getPath());
        assertEquals(200, afterTimeout.statusCode());
        assertFalse(afterTimeout.body().contains("Signed in as"));
    }

    private HttpResponse<String> get(HttpClient client, String url)
            throws IOException, InterruptedException {
        return client.send(HttpRequest.newBuilder(URI.create(url)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> postForm(HttpClient client, String url, String body)
            throws IOException, InterruptedException {
        return client.send(HttpRequest.newBuilder(URI.create(url))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private String csrfToken(String html) {
        Matcher matcher = CSRF_INPUT.matcher(html);
        if (!matcher.find()) {
            throw new IllegalStateException("The rendered form did not include a CSRF token.");
        }
        return matcher.group(1);
    }

    private String form(String... values) {
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < values.length; i += 2) {
            if (!body.isEmpty()) {
                body.append('&');
            }
            body.append(encode(values[i])).append('=').append(encode(values[i + 1]));
        }
        return body.toString();
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}

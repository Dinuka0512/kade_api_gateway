package com.dinuka.dev.api_gateway.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Validates the Bearer JWT at the edge, strips any client-supplied identity
 * headers (anti-spoofing) and forwards the verified identity to downstream
 * services via trusted X-User-* headers.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final String HEADER_USER_ID = "X-User-Id";
    public static final String HEADER_USER_EMAIL = "X-User-Email";
    public static final String HEADER_USER_NAME = "X-User-Name";
    public static final String HEADER_USER_ROLE = "X-User-Role";

    private static final Set<String> TRUSTED_HEADERS = Set.of(
            HEADER_USER_ID, HEADER_USER_EMAIL, HEADER_USER_NAME, HEADER_USER_ROLE);

    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final SecretKey key;

    public JwtAuthenticationFilter(
            @Value("${jwt.secret:kade-secret-key-that-is-long-enough-for-hs256-algorithm}") String secret) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        IdentityRequestWrapper wrappedRequest = new IdentityRequestWrapper(request);

        String authHeader = wrappedRequest.getHeader(AUTH_HEADER);
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            filterChain.doFilter(wrappedRequest, response);
            return;
        }

        String token = authHeader.substring(BEARER_PREFIX.length()).trim();
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            if (claims.getExpiration() != null && claims.getExpiration().before(new java.util.Date())) {
                reject(response, "Session expired. Please sign in again.");
                return;
            }

            String role = claims.get("role", String.class);
            if (role == null || role.isBlank()) {
                reject(response, "Invalid session token.");
                return;
            }

            wrappedRequest.putTrustedHeader(HEADER_USER_ID, claims.getSubject());
            wrappedRequest.putTrustedHeader(HEADER_USER_EMAIL, claims.get("email", String.class));
            wrappedRequest.putTrustedHeader(HEADER_USER_NAME, claims.get("name", String.class));
            wrappedRequest.putTrustedHeader(HEADER_USER_ROLE, role);

            filterChain.doFilter(wrappedRequest, response);
        } catch (JwtException | IllegalArgumentException e) {
            reject(response, "Invalid or expired session. Please sign in again.");
        }
    }

    private void reject(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write("{\"message\": \"" + message + "\"}");
    }

    /**
     * Removes any client-supplied X-User-* headers so they can never be
     * spoofed, then exposes only the gateway-verified values.
     */
    static class IdentityRequestWrapper extends HttpServletRequestWrapper {

        private final Map<String, String> trustedHeaders = new HashMap<>();

        IdentityRequestWrapper(HttpServletRequest request) {
            super(request);
        }

        void putTrustedHeader(String name, String value) {
            if (value != null && !value.isBlank()) {
                trustedHeaders.put(name, value);
            }
        }

        private boolean isTrusted(String name) {
            String lower = name.toLowerCase();
            for (String trusted : TRUSTED_HEADERS) {
                if (trusted.toLowerCase().equals(lower)) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public String getHeader(String name) {
            if (isTrusted(name)) {
                for (String trusted : TRUSTED_HEADERS) {
                    if (trusted.equalsIgnoreCase(name)) {
                        return trustedHeaders.get(trusted);
                    }
                }
            }
            return super.getHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            if (isTrusted(name)) {
                for (String trusted : TRUSTED_HEADERS) {
                    if (trusted.equalsIgnoreCase(name)) {
                        String value = trustedHeaders.get(trusted);
                        return value != null
                                ? Collections.enumeration(List.of(value))
                                : Collections.emptyEnumeration();
                    }
                }
            }
            return super.getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            Set<String> names = new HashSet<>(Collections.list(super.getHeaderNames()));
            names.removeIf(this::isTrusted);
            names.addAll(trustedHeaders.keySet());
            return Collections.enumeration(names);
        }
    }
}

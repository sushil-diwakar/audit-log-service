package com.example.auditlog.config;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    // Bounded LRU cache to prevent memory exhaustion
    private final Map<String, Bucket> buckets = java.util.Collections.synchronizedMap(
        new java.util.LinkedHashMap<String, Bucket>(1000, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Bucket> eldest) {
                return size() > 10000;
            }
        });

    @Value("${audit.rate-limit.capacity:100}")
    private long capacity;

    @Value("${audit.rate-limit.refill-tokens:100}")
    private long refillTokens;

    @Value("${audit.rate-limit.export-capacity:10}")
    private long exportCapacity;

    @Value("${audit.rate-limit.export-refill-tokens:10}")
    private long exportRefillTokens;

    @Value("${audit.rate-limit.trusted-proxies:}")
    private String trustedProxies;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Skip rate limiting for CORS preflight and health checks
        if ("OPTIONS".equalsIgnoreCase(request.getMethod()) ||
            request.getRequestURI().startsWith("/actuator")) {
            filterChain.doFilter(request, response);
            return;
        }

        String key = resolveKey(request);
        Bucket bucket = buckets.computeIfAbsent(key, k -> createNewBucket(request.getRequestURI()));

        if (bucket.tryConsume(1)) {
            filterChain.doFilter(request, response);
        } else {
            log.warn("Rate limit exceeded for key: {}, path: {}", key, request.getRequestURI());
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType("application/json");
            response.setHeader("Retry-After", "60");
            response.getWriter().write("{\"error\": \"Too Many Requests\", \"message\": \"Rate limit exceeded. Please try again later.\"}");
        }
    }

    private String resolveKey(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // Prioritize authenticated user identity for rate limiting
        if (auth != null && auth.isAuthenticated() && !auth.getPrincipal().equals("anonymousUser")) {
            String principal = auth.getName();
            // Include path in key for per-endpoint limits
            return principal + ":" + getEndpointCategory(request.getRequestURI());
        }

        // Fallback to IP-based rate limiting for unauthenticated requests
        String ip = extractClientIp(request);
        return "ip:" + ip + ":" + getEndpointCategory(request.getRequestURI());
    }

    private String extractClientIp(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();

        // SECURITY: Only trust X-Forwarded-For if request comes from a trusted proxy
        // This prevents header spoofing attacks where attackers bypass rate limits
        // by sending fake X-Forwarded-For headers
        if (isTrustedProxy(remoteAddr)) {
            String xForwardedFor = request.getHeader("X-Forwarded-For");
            if (xForwardedFor != null && !xForwardedFor.isBlank()) {
                // Take first IP in chain (original client)
                return xForwardedFor.split(",")[0].trim();
            }

            String xRealIp = request.getHeader("X-Real-IP");
            if (xRealIp != null && !xRealIp.isBlank()) {
                return xRealIp;
            }
        }

        // If not from trusted proxy, or no forwarding headers, use direct connection IP
        return remoteAddr;
    }

    /**
     * Checks if the given IP address is in the trusted proxy list.
     * Only requests from trusted proxies are allowed to use X-Forwarded-For headers.
     *
     * @param ip The IP address to check
     * @return true if the IP is a trusted proxy, false otherwise
     */
    private boolean isTrustedProxy(String ip) {
        if (trustedProxies == null || trustedProxies.isBlank()) {
            // No trusted proxies configured - don't trust any forwarding headers
            return false;
        }

        String[] proxies = trustedProxies.split(",");
        for (String proxy : proxies) {
            if (proxy.trim().equals(ip)) {
                return true;
            }
        }

        return false;
    }

    private String getEndpointCategory(String uri) {
        if (uri.startsWith("/audit/export")) {
            return "export";
        } else if (uri.startsWith("/audit/events") && uri.contains("/redact")) {
            return "redact";
        } else if (uri.startsWith("/audit/events")) {
            return "events";
        } else if (uri.startsWith("/audit/verify")) {
            return "verify";
        }
        return "other";
    }

    private Bucket createNewBucket(String uri) {
        // Export endpoints have stricter limits (expensive operations)
        if (uri.startsWith("/audit/export")) {
            Refill refill = Refill.greedy(exportRefillTokens, Duration.ofMinutes(1));
            Bandwidth limit = Bandwidth.classic(exportCapacity, refill);
            return Bucket.builder().addLimit(limit).build();
        }

        // Standard rate limit for all other endpoints
        Refill refill = Refill.greedy(refillTokens, Duration.ofMinutes(1));
        Bandwidth limit = Bandwidth.classic(capacity, refill);
        return Bucket.builder().addLimit(limit).build();
    }
}

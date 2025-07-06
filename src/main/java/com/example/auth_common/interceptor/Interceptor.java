package com.example.auth_common.interceptor;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Component
public class Interceptor implements HandlerInterceptor {

    @Value("${auth.secret-key}")
    private String SECRET_KEY;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

        System.out.println("🔥 Interceptor 들어옴: " + request.getRequestURI());

        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true;
        }

        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        }

        for (Cookie cookie : cookies) {
            if ("memberId".equals(cookie.getName())) {
                String[] parts = cookie.getValue().split("\\|");
                if (parts.length != 2) break;

                String memberId = parts[0];
                String signature = parts[1];

                String expectedSig = hmacSha256(memberId, SECRET_KEY);

                if (expectedSig.equals(signature)) {
                    request.setAttribute("authenticatedMemberId", memberId); // Controller에서 꺼내쓸 수 있도록 저장
                    return true;
                }
            }
        }

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        return false;
    }

    private String hmacSha256(String value, String key) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            hmac.init(keySpec);
            byte[] hash = hmac.doFinal(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("HMAC 생성 실패", e);
        }
    }
}
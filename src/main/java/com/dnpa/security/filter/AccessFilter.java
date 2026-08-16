package com.dnpa.security.filter;


import com.dnpa.common.constants.PublicApi;

import com.dnpa.security.core.AccountAuthentication;
import com.dnpa.security.core.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.ThreadContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;
import java.util.UUID;

@Component(value = "accessFilter")
@Slf4j
public class AccessFilter extends OncePerRequestFilter {
    @Autowired
    private com.dnpa.security.core.jwt.JwtTokenProvider jwtTokenProvider;
    
    @Autowired
    private org.springframework.data.redis.core.StringRedisTemplate stringRedisTemplate;

    public static final String SUPER_USER_HEADER = "SUPER_USER";
    public static final String SUPER_USER = "DNPA29122002";
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String SUPER_USER_TOKEN = "DNPA29122002";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            String path = request.getRequestURI();
            ThreadContext.put("APIUrl", path);
            ThreadContext.put("UUID", String.valueOf(UUID.randomUUID()));
            if (!request.getRequestURI().contains("actuator/health")) {
                log.info("Start API: " + path);
            }
            String superUser = request.getHeader(SUPER_USER_HEADER);
            if ((superUser != null && superUser.equals(SUPER_USER)) || PublicApi.isPublicApi(request.getRequestURI()) || PublicApi.isWebSocketEndpoint(request.getRequestURI())) {
                CustomUserDetails customUserDetails = CustomUserDetails.getSuperUser();
                AccountAuthentication accountAuthentication = AccountAuthentication.builder().customUserDetails(customUserDetails)
                        .accessToken(SUPER_USER_TOKEN).build();
                SecurityContextHolder.getContext()
                        .setAuthentication(accountAuthentication);

                filterChain.doFilter(request, response);
                return;
            }
            
            String jwt = getJwtFromCookie(request);
            if (jwt != null && !jwt.isEmpty() && jwtTokenProvider.validateJwtToken(jwt)) {
                String sessionId = jwtTokenProvider.getSessionIdFromJWT(jwt);
                if (sessionId != null) {
                    String sessionJson = stringRedisTemplate.opsForValue().get("session:" + sessionId);
                    if (sessionJson != null && sessionJson.contains("\"status\":1")) { // Simple check for active session
                        Long userId = jwtTokenProvider.getUserIdFromJWT(jwt);
                        CustomUserDetails customUserDetails = CustomUserDetails.build(userId, userId.toString(), java.util.List.of("USER"));
                        
                        SecurityContextHolder.getContext().setAuthentication(
                                AccountAuthentication.builder()
                                        .customUserDetails(customUserDetails)
                                        .accessToken(jwt)
                                        .build());
                        filterChain.doFilter(request, response);
                        return;
                    }
                }
            }
            response.setStatus(HttpStatus.SC_UNAUTHORIZED);


        } catch (Exception e) {
            log.error("AccessFilter: " + e);

            response.setStatus(HttpStatus.SC_UNAUTHORIZED);
        }
    }

    private String getJwtFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if(Objects.isNull(cookies)) {
            return "";
        }
        for (Cookie cookie : cookies) {
            String cookieName = cookie.getName();
            String cookieValue = cookie.getValue();
            if (StringUtils.hasText(cookieName) && cookieName.equals(AUTHORIZATION_HEADER)) {
                return cookieValue;
            }
        }
        return "";
    }
}



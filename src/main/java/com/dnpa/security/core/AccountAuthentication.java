package com.dnpa.security.core;

import lombok.Builder;
import lombok.Data;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;
@Data
@Builder
public class AccountAuthentication implements Authentication {
    private CustomUserDetails customUserDetails;
    private String accessToken;
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();
    }

    public AccountAuthentication(CustomUserDetails customUserDetails, String accessToken) {
        this.customUserDetails = customUserDetails;
        this.accessToken = accessToken;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getDetails() {
        return customUserDetails;
    }

    @Override
    public Object getPrincipal() {
        return customUserDetails;
    }

    @Override
    public boolean isAuthenticated() {
        return customUserDetails != null;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

    }

    @Override
    public String getName() {
        return "";
    }
}


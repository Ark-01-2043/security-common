package com.dnpa.security.config;

import com.dnpa.security.core.CustomUserDetails;
import com.dnpa.common.enums.AccountRole;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

public class CustomMethodSecurityExpressionRoot extends SecurityExpressionRoot implements MethodSecurityExpressionOperations {

    public CustomMethodSecurityExpressionRoot(Authentication authentication) {
        super(authentication);
    }

    public boolean isSuperAdmin() {
        return hasAccountRole("ADMIN");
    }

    public boolean hasAccountRole(String role) {
        if (this.getPrincipal() instanceof CustomUserDetails) {
            CustomUserDetails userDetails = (CustomUserDetails) this.getPrincipal();
            return userDetails.haveRole(role);
        }
        return false;
    }

    @Override
    public void setFilterObject(Object filterObject) {}

    @Override
    public Object getFilterObject() { return null; }

    @Override
    public void setReturnObject(Object returnObject) {}

    @Override
    public Object getReturnObject() { return null; }

    @Override
    public Object getThis() { return this; }
}

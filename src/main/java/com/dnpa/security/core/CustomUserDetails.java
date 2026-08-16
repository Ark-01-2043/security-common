package com.dnpa.security.core;


import com.dnpa.common.enums.AccountStatus;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Data
public class CustomUserDetails implements Serializable, UserDetails {

    public static final String SUPER_USER = "SUPERADMIN";
    
    private Long id;
    private String username;
    private String email;
    private String phoneNumber;
    private String password;
    private Short status;
    private Boolean isEmailVerified;
    private List<String> roles;
    private List<String> permissions;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (roles == null) return List.of();
        return roles.stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)).collect(Collectors.toList());
    }

    public CustomUserDetails() {
        super();
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return id != null ? id.toString() : username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return status != null && status == 1; // 1: Active
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return isAccountNonLocked();
    }

    public boolean haveRole(String roleCode) {
        return roles != null && roles.contains(roleCode);
    }

    public boolean havePermission(String permissionCode) {
        return permissions != null && permissions.contains(permissionCode);
    }

    public static CustomUserDetails build(Long id, String username, List<String> roles) {
        CustomUserDetails customUserDetails = new CustomUserDetails();
        customUserDetails.setId(id);
        customUserDetails.setUsername(username);
        customUserDetails.setStatus((short) 1);
        customUserDetails.setRoles(roles);
        return customUserDetails;
    }

    public static CustomUserDetails getSuperUser() {
        CustomUserDetails customUserDetails = new CustomUserDetails();
        customUserDetails.setId(0L);
        customUserDetails.setUsername(SUPER_USER);
        customUserDetails.setEmail("admin@localhost");
        customUserDetails.setStatus((short) 1);
        customUserDetails.setIsEmailVerified(true);
        customUserDetails.setRoles(List.of("ADMIN"));
        return customUserDetails;
    }
}

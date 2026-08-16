package com.dnpa.security.config;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ApiAuthority {

    public Map<String, List<String>> authorities = new HashMap<>();

    public static ApiAuthority getApiAuthority(String url) {
        ApiAuthority apiAuthority = new ApiAuthority();
        // Default implementation, returning empty authorities
        // This is a dummy implementation since the original file was lost
        return apiAuthority;
    }
}

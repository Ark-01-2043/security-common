package com.dnpa.security.dto.request;

import com.dnpa.security.core.CustomUserDetails;
import lombok.Builder;
import lombok.Data;

import java.io.Serializable;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Map;

@Data
@Builder
public class Request implements Serializable {
    private String method;
    private String screenId;
    private String url;
    private Timestamp timestamp = new Timestamp(Calendar.getInstance().getTime().getTime());
    private Map<String, String> parameters;
    private Map<String, String> headers;
    private String body;
    private String ipAddress;
    private CustomUserDetails userDetails;
}

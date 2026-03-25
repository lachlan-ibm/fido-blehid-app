/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.util.http;

import java.util.Map;

/**
 * HTTP response wrapper containing status code, headers, and body.
 */
public class HttpResponse {
    private final int statusCode;
    private final Map<String, String> headers;
    private final String body;
    private final boolean successful;

    public HttpResponse(int statusCode, Map<String, String> headers, String body) {
        this.statusCode = statusCode;
        this.headers = headers;
        this.body = body;
        this.successful = statusCode >= 200 && statusCode < 300;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public String getBody() {
        return body;
    }

    public boolean isSuccessful() {
        return successful;
    }

    public String getHeader(String name) {
        return headers.get(name);
    }

    @Override
    public String toString() {
        return "HttpResponse{" +
                "statusCode=" + statusCode +
                ", successful=" + successful +
                ", bodyLength=" + (body != null ? body.length() : 0) +
                '}';
    }
}

// Made with Bob

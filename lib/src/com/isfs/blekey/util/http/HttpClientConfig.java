/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.util.http;

/**
 * HTTP client timeout configuration.
 * Short timeouts keep the app responsive and prevent hanging on slow/unresponsive servers.
 */
public class HttpClientConfig {
    public static final int CONNECT_TIMEOUT_MS = 5000;    // 5 seconds to establish connection
    public static final int READ_TIMEOUT_MS = 10000;      // 10 seconds for data transfer
    public static final int WRITE_TIMEOUT_MS = 10000;     // 10 seconds for upload
    
    private HttpClientConfig() {
    }
}

// Made with Bob

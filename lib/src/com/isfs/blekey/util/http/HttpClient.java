/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.util.http;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Simple HTTP client with JSON request/response handling, error handling, and retry logic.
 * Uses OkHttp for Android optimization and HTTP/2 support.
 */
public class HttpClient {
    private static final Logger logger = LoggerFactory.getLogger(HttpClient.class);
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    
    private final OkHttpClient client;

    public HttpClient() {
        this.client = new OkHttpClient.Builder()
            .connectTimeout(HttpClientConfig.CONNECT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .readTimeout(HttpClientConfig.READ_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .writeTimeout(HttpClientConfig.WRITE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .build();
    }

    /**
     * Perform HTTP GET request.
     */
    public HttpResponse get(String url) throws HttpException {
        return get(url, null);
    }

    /**
     * Perform HTTP GET request with custom headers.
     */
    public HttpResponse get(String url, Map<String, String> headers) throws HttpException {
        Request.Builder builder = new Request.Builder().url(url);
        
        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                builder.addHeader(entry.getKey(), entry.getValue());
            }
        }
        
        Request request = builder.build();
        return executeRequest(request);
    }

    /**
     * Perform HTTP POST request with JSON body.
     */
    public HttpResponse post(String url, String jsonBody) throws HttpException {
        return post(url, jsonBody, null);
    }

    /**
     * Perform HTTP POST request with JSON body and custom headers.
     */
    public HttpResponse post(String url, String jsonBody, Map<String, String> headers) throws HttpException {
        RequestBody body = RequestBody.create(jsonBody, JSON);
        Request.Builder builder = new Request.Builder()
            .url(url)
            .post(body);
        
        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                builder.addHeader(entry.getKey(), entry.getValue());
            }
        }
        
        Request request = builder.build();
        return executeRequest(request);
    }

    /**
     * Perform HTTP GET request with retry logic.
     */
    public HttpResponse getWithRetry(String url, Map<String, String> headers, RetryPolicy retryPolicy) throws HttpException {
        return executeWithRetry(() -> get(url, headers), retryPolicy);
    }

    /**
     * Perform HTTP POST request with retry logic.
     */
    public HttpResponse postWithRetry(String url, String jsonBody, Map<String, String> headers, RetryPolicy retryPolicy) throws HttpException {
        return executeWithRetry(() -> post(url, jsonBody, headers), retryPolicy);
    }

    /**
     * Execute request with retry logic.
     */
    private HttpResponse executeWithRetry(HttpOperation operation, RetryPolicy retryPolicy) throws HttpException {
        HttpException lastException = null;
        
        for (int attempt = 0; attempt <= retryPolicy.getMaxRetries(); attempt++) {
            try {
                return operation.execute();
            } catch (HttpException e) {
                lastException = e;
                
                if (attempt < retryPolicy.getMaxRetries() && retryPolicy.shouldRetry(e.getErrorType())) {
                    long backoff = retryPolicy.getBackoffMs(attempt);
                    logger.warn("Request failed (attempt {}/{}), retrying in {}ms: {}", 
                        attempt + 1, retryPolicy.getMaxRetries() + 1, backoff, e.getMessage());
                    
                    try {
                        Thread.sleep(backoff);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new HttpException.NetworkException("Retry interrupted", ie);
                    }
                } else {
                    break;
                }
            }
        }
        
        throw lastException;
    }

    /**
     * Execute HTTP request and convert to HttpResponse.
     */
    private HttpResponse executeRequest(Request request) throws HttpException {
        try {
            Response response = client.newCall(request).execute();
            
            Map<String, String> headers = new HashMap<>();
            for (String name : response.headers().names()) {
                headers.put(name, response.header(name));
            }
            
            String body = null;
            if (response.body() != null) {
                body = response.body().string();
            }
            
            int statusCode = response.code();
            
            if (statusCode >= 500) {
                throw new HttpException.ServerException(
                    "Server error: " + statusCode, statusCode);
            }
            
            return new HttpResponse(statusCode, headers, body);
            
        } catch (java.net.SocketTimeoutException e) {
            throw new HttpException.TimeoutException("Request timed out: " + e.getMessage());
        } catch (IOException e) {
            throw new HttpException.NetworkException("Network error: " + e.getMessage(), e);
        }
    }

    @FunctionalInterface
    private interface HttpOperation {
        HttpResponse execute() throws HttpException;
    }
}

// Made with Bob

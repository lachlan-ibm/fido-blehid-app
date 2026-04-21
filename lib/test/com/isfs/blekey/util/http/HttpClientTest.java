/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.util.http;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for HttpClient.
 */
public class HttpClientTest {
    private MockWebServer mockServer;
    private HttpClient httpClient;
    private String baseUrl;

    @BeforeEach
    public void setUp() throws Exception {
        mockServer = new MockWebServer();
        mockServer.start();
        baseUrl = mockServer.url("/").toString();
        httpClient = new HttpClient();
    }

    @AfterEach
    public void tearDown() throws Exception {
        mockServer.shutdown();
    }

    @Test
    public void testGetRequest() throws Exception {
        mockServer.enqueue(new MockResponse()
            .setResponseCode(200)
            .setBody("{\"status\":\"ok\"}")
            .addHeader("Content-Type", "application/json"));

        HttpResponse response = httpClient.get(baseUrl + "test");

        assertEquals(200, response.getStatusCode());
        assertTrue(response.isSuccessful());
        assertEquals("{\"status\":\"ok\"}", response.getBody());
        assertEquals("application/json", response.getHeader("Content-Type"));

        RecordedRequest request = mockServer.takeRequest();
        assertEquals("GET", request.getMethod());
        assertEquals("/test", request.getPath());
    }

    @Test
    public void testGetRequestWithHeaders() throws Exception {
        mockServer.enqueue(new MockResponse()
            .setResponseCode(200)
            .setBody("{}"));

        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer token123");
        headers.put("X-Custom-Header", "value");

        httpClient.get(baseUrl + "test", headers);

        RecordedRequest request = mockServer.takeRequest();
        assertEquals("Bearer token123", request.getHeader("Authorization"));
        assertEquals("value", request.getHeader("X-Custom-Header"));
    }

    @Test
    public void testPostRequest() throws Exception {
        mockServer.enqueue(new MockResponse()
            .setResponseCode(201)
            .setBody("{\"id\":\"123\"}"));

        String jsonBody = "{\"name\":\"test\"}";
        HttpResponse response = httpClient.post(baseUrl + "create", jsonBody);

        assertEquals(201, response.getStatusCode());
        assertTrue(response.isSuccessful());
        assertEquals("{\"id\":\"123\"}", response.getBody());

        RecordedRequest request = mockServer.takeRequest();
        assertEquals("POST", request.getMethod());
        assertEquals("/create", request.getPath());
        assertEquals(jsonBody, request.getBody().readUtf8());
        assertTrue(request.getHeader("Content-Type").contains("application/json"));
    }

    @Test
    public void testPostRequestWithHeaders() throws Exception {
        mockServer.enqueue(new MockResponse()
            .setResponseCode(200)
            .setBody("{}"));

        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer token123");

        httpClient.post(baseUrl + "test", "{}", headers);

        RecordedRequest request = mockServer.takeRequest();
        assertEquals("Bearer token123", request.getHeader("Authorization"));
    }

    @Test
    public void testServerError() {
        mockServer.enqueue(new MockResponse()
            .setResponseCode(500)
            .setBody("Internal Server Error"));

        HttpException exception = assertThrows(HttpException.ServerException.class, () -> {
            httpClient.get(baseUrl + "error");
        });

        assertTrue(exception instanceof HttpException.ServerException);
        assertEquals(500, ((HttpException.ServerException) exception).getStatusCode());
    }

    @Test
    public void testRetryOnNetworkError() throws Exception {
        mockServer.enqueue(new MockResponse().setSocketPolicy(okhttp3.mockwebserver.SocketPolicy.DISCONNECT_AT_START));
        mockServer.enqueue(new MockResponse()
            .setResponseCode(200)
            .setBody("{\"status\":\"ok\"}"));

        HttpResponse response = httpClient.getWithRetry(baseUrl + "test", null, RetryPolicy.ISSUANCE);

        assertEquals(200, response.getStatusCode());
        assertEquals(2, mockServer.getRequestCount());
    }

    @Test
    public void testRetryExhaustion() {
        mockServer.enqueue(new MockResponse().setSocketPolicy(okhttp3.mockwebserver.SocketPolicy.DISCONNECT_AT_START));
        mockServer.enqueue(new MockResponse().setSocketPolicy(okhttp3.mockwebserver.SocketPolicy.DISCONNECT_AT_START));
        mockServer.enqueue(new MockResponse().setSocketPolicy(okhttp3.mockwebserver.SocketPolicy.DISCONNECT_AT_START));

        assertThrows(HttpException.NetworkException.class, () -> {
            httpClient.getWithRetry(baseUrl + "test", null, RetryPolicy.ISSUANCE);
        });

        assertEquals(3, mockServer.getRequestCount());
    }

    @Test
    public void testNoRetryForPresentation() {
        mockServer.enqueue(new MockResponse().setSocketPolicy(okhttp3.mockwebserver.SocketPolicy.DISCONNECT_AT_START));

        assertThrows(HttpException.NetworkException.class, () -> {
            httpClient.getWithRetry(baseUrl + "test", null, RetryPolicy.PRESENTATION);
        });

        assertEquals(1, mockServer.getRequestCount());
    }

    @Test
    public void testClientErrorNoRetry() {
        mockServer.enqueue(new MockResponse()
            .setResponseCode(401)
            .setBody("Unauthorized"));

        HttpResponse response = assertDoesNotThrow(() -> {
            return httpClient.getWithRetry(baseUrl + "test", null, RetryPolicy.ISSUANCE);
        });

        assertEquals(401, response.getStatusCode());
        assertFalse(response.isSuccessful());
        assertEquals(1, mockServer.getRequestCount());
    }
}

// Made with Bob

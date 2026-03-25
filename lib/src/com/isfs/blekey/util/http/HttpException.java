/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.util.http;

/**
 * Base exception for HTTP-related errors.
 */
public class HttpException extends Exception {
    private final RetryPolicy.ErrorType errorType;

    public HttpException(String message, RetryPolicy.ErrorType errorType) {
        super(message);
        this.errorType = errorType;
    }

    public HttpException(String message, Throwable cause, RetryPolicy.ErrorType errorType) {
        super(message, cause);
        this.errorType = errorType;
    }

    public RetryPolicy.ErrorType getErrorType() {
        return errorType;
    }

    public static class NetworkException extends HttpException {
        public NetworkException(String message, Throwable cause) {
            super(message, cause, RetryPolicy.ErrorType.NETWORK_ERROR);
        }
    }

    public static class TimeoutException extends HttpException {
        public TimeoutException(String message) {
            super(message, RetryPolicy.ErrorType.TIMEOUT);
        }
    }

    public static class ServerException extends HttpException {
        private final int statusCode;

        public ServerException(String message, int statusCode) {
            super(message, RetryPolicy.ErrorType.SERVER_ERROR_5XX);
            this.statusCode = statusCode;
        }

        public int getStatusCode() {
            return statusCode;
        }
    }
}

// Made with Bob

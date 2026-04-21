/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.util.http;

/**
 * Retry policy configuration for different HTTP operations.
 */
public class RetryPolicy {
    private final int maxRetries;
    private final long[] backoffMs;
    private final ErrorType[] retryableErrors;

    public enum ErrorType {
        NETWORK_ERROR,
        TIMEOUT,
        SERVER_ERROR_5XX
    }

    public RetryPolicy(int maxRetries, long[] backoffMs, ErrorType[] retryableErrors) {
        this.maxRetries = maxRetries;
        this.backoffMs = backoffMs;
        this.retryableErrors = retryableErrors;
    }

    public int getMaxRetries() {
        return maxRetries;
    }

    public long getBackoffMs(int retryAttempt) {
        if (retryAttempt >= backoffMs.length) {
            return backoffMs[backoffMs.length - 1];
        }
        return backoffMs[retryAttempt];
    }

    public boolean shouldRetry(ErrorType errorType) {
        for (ErrorType retryable : retryableErrors) {
            if (retryable == errorType) {
                return true;
            }
        }
        return false;
    }

    // Issuance: Retry on network errors, not on auth errors
    public static final RetryPolicy ISSUANCE = new RetryPolicy(
        2,
        new long[]{1000, 2000},
        new ErrorType[]{ErrorType.NETWORK_ERROR, ErrorType.TIMEOUT}
    );

    // Presentation: No retries (time-sensitive, verifier waiting)
    public static final RetryPolicy PRESENTATION = new RetryPolicy(
        0,
        new long[]{},
        new ErrorType[]{}
    );

    // Status check: Retry with exponential backoff
    public static final RetryPolicy STATUS_CHECK = new RetryPolicy(
        3,
        new long[]{2000, 4000, 8000},
        new ErrorType[]{ErrorType.NETWORK_ERROR, ErrorType.TIMEOUT, ErrorType.SERVER_ERROR_5XX}
    );
}

// Made with Bob

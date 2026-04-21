/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.credential.status;

import com.isfs.blekey.credential.DigitalCredentialMetadata;
import com.isfs.blekey.credential.VerifiableCredential;
import com.isfs.blekey.util.http.HttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Main interface for checking credential status.
 * Coordinates fetching and parsing of status lists.
 */
public class CredentialStatusChecker {
    
    private static final Logger logger = LoggerFactory.getLogger(CredentialStatusChecker.class);
    
    private final StatusList2021 statusList2021;
    
    public CredentialStatusChecker() {
        this.statusList2021 = new StatusList2021();
    }
    
    public CredentialStatusChecker(HttpClient httpClient) {
        this.statusList2021 = new StatusList2021(httpClient);
    }
    
    /**
     * Checks the status of a verifiable credential.
     * 
     * @param credential The credential to check
     * @return Credential status
     */
    public CredentialStatus checkStatus(VerifiableCredential credential) {
        if (credential == null) {
            logger.warn("Cannot check status of null credential");
            return CredentialStatus.UNKNOWN;
        }
        
        DigitalCredentialMetadata metadata = credential.getMetadata();
        if (metadata == null) {
            logger.warn("Credential has no metadata");
            return CredentialStatus.UNKNOWN;
        }
        
        String statusListUrl = metadata.getStatusListUrl();
        if (statusListUrl == null || statusListUrl.isEmpty()) {
            logger.debug("Credential has no status list URL, assuming valid");
            return CredentialStatus.VALID;
        }
        
        try {
            // Extract status list index from credential
            // For MVP, we'll assume it's stored in display properties
            String indexStr = metadata.getDisplayProperty("statusListIndex");
            if (indexStr == null) {
                logger.warn("Status list index not found in credential");
                return CredentialStatus.UNKNOWN;
            }
            
            int statusListIndex = Integer.parseInt(indexStr);
            
            logger.debug("Checking status for credential {}: url={}, index={}", 
                        credential.getId(), statusListUrl, statusListIndex);
            
            return statusList2021.checkStatus(statusListUrl, statusListIndex);
            
        } catch (NumberFormatException e) {
            logger.error("Invalid status list index", e);
            return CredentialStatus.UNKNOWN;
        } catch (StatusListException e) {
            logger.error("Failed to check credential status", e);
            return CredentialStatus.UNKNOWN;
        }
    }
    
    /**
     * Checks if a credential is valid (not revoked or suspended).
     * 
     * @param credential The credential to check
     * @return true if credential is valid, false otherwise
     */
    public boolean isValid(VerifiableCredential credential) {
        CredentialStatus status = checkStatus(credential);
        return status == CredentialStatus.VALID;
    }
    
    /**
     * Checks if a credential is revoked.
     * 
     * @param credential The credential to check
     * @return true if credential is revoked, false otherwise
     */
    public boolean isRevoked(VerifiableCredential credential) {
        CredentialStatus status = checkStatus(credential);
        return status == CredentialStatus.REVOKED;
    }
    
    /**
     * Clears the status list cache.
     */
    public void clearCache() {
        statusList2021.clearCache();
    }
    
    /**
     * Clears a specific status list from cache.
     * 
     * @param statusListUrl The status list URL to clear
     */
    public void clearCache(String statusListUrl) {
        statusList2021.clearCache(statusListUrl);
    }
}

// Made with Bob
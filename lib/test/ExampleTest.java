/*
 * Copyright IBM 2025, 2026
 */
import com.isfs.blekey.authenticator.*;

import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;

public class ExampleTest {
    
    @Test
    public void testAuthenticatorWithConfigAndHelper() throws Exception {
        // Use TestConfig to get configuration values
        String algorithm = TestConfig.getKeyAlgorithm();
        int keySize = TestConfig.getKeySize();
        String attestationType = TestConfig.getAttestationType();
        
        // Use TestHelper to create test objects
        KeyPair keyPair = TestHelper.createTestKeyPair(algorithm);
        Object[] caData = TestHelper.createTestCA();
        KeyPair caKeyPair = (KeyPair) caData[0];
        X509Certificate caCert = (X509Certificate) caData[1];
        
        // Create the authenticator with the configured algorithm
        Fido2Authenticator authenticator = new Fido2Authenticator(algorithm, keySize);
        
        // Use TestHelper to get test data
        String jsonOptions = TestHelper.createCredentialCreationOptionsJson();
        System.err.println(jsonOptions);
        
        // Perform the test
        String response = authenticator.credentialCreate(jsonOptions, attestationType, keyPair, caKeyPair, caCert);
        System.err.println(response);
        
        // Assert on the result
        assertNotNull(response);
        assertTrue(response.contains("attestationObject"));
    }
}

// Made with Bob

/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.data;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import com.isfs.blekey.util.FileUtils;
import com.isfs.blekey.util.KeyUtils;

import static org.junit.Assert.*;

/**
 * Test class specifically for testing the main method of Passkey class.
 */
public class PasskeyMainTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();
    
    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    private final ByteArrayOutputStream errContent = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;
    private final PrintStream originalErr = System.err;
    private java.io.InputStream originalIn = System.in;

    private String fido2Home;
    private KeyPair rootKeyPair;
    
    @Before
    public void setUp() throws Exception {
        // Reset output streams for each test
        outContent.reset();
        errContent.reset();

        // Redirect stdout and stderr
        System.setOut(new PrintStream(outContent));
        System.setErr(new PrintStream(errContent));
        
        // Save original stdin
        originalIn = System.in;
        
        // Create a temporary FIDO2_HOME directory with a unique name for each test
        fido2Home = tempFolder.newFolder("fido2_home_" + System.currentTimeMillis()).getAbsolutePath();
        
        // Generate a root key pair for testing
        rootKeyPair = KeyUtils.generateKeyPair("EC", 521);
        
        // Initialize KeystoreManager for Passkey operations
        Passkey.setKeystoreManager(com.isfs.blekey.authenticator.TestHelper.createMockKeystoreManager());
    }
    
    @After
    public void tearDown() throws Exception {
        // Restore stdout, stderr, and stdin
        System.setOut(originalOut);
        System.setErr(originalErr);
        System.setIn(originalIn);
        
        // Reset static fields to prevent test pollution
        Field rootPublicKeyField = Passkey.class.getDeclaredField("rootPublicKey");
        rootPublicKeyField.setAccessible(true);
        rootPublicKeyField.set(null, null);
        
        Field rootPrivateKeyField = Passkey.class.getDeclaredField("rootPrivateKey");
        rootPrivateKeyField.setAccessible(true);
        rootPrivateKeyField.set(null, null);
        
        // Explicitly delete any passkey and stash files that might have been created
        if (fido2Home != null) {
            File dir = new File(fido2Home);
            if (dir.exists()) {
                File[] files = dir.listFiles((d, name) -> name.endsWith(".passkey") || name.endsWith(".stash"));
                if (files != null) {
                    for (File file : files) {
                        if (!file.delete()) {
                            originalErr.println("Warning: Failed to delete file: " + file.getAbsolutePath());
                        }
                    }
                }
            }
        }
    }
    
    /**
     * Helper method to set the root key pair in the Passkey class using reflection
     */
    private void setRootKeyPair(PublicKey publicKey, PrivateKey privateKey) throws Exception {
        Field rootPublicKeyField = Passkey.class.getDeclaredField("rootPublicKey");
        rootPublicKeyField.setAccessible(true);
        rootPublicKeyField.set(null, publicKey);
        
        Field rootPrivateKeyField = Passkey.class.getDeclaredField("rootPrivateKey");
        rootPrivateKeyField.setAccessible(true);
        rootPrivateKeyField.set(null, privateKey);
    }

    private void logOutErr() {
        originalErr.println("Error output: " + errContent.toString());
        originalErr.println("Standard output: " + outContent.toString());
    }
    
    /**
     * Helper method to get a unique file name for each test
     */
    private File getUniquePasskeyFile(String baseName) {
        return new File(fido2Home + File.separator + baseName + "_" + System.currentTimeMillis() + ".passkey");
    }
    
    /**
     * Test the main method with 'generate' command
     */
    @Test
    public void testMainWithGenerateCommand() throws Exception {
        originalErr.println("testMainWithGenerateCommand");
        // Mock FileUtils.getFido2Home() to return our temporary directory
        try (MockedStatic<FileUtils> mockedFileUtils = Mockito.mockStatic(FileUtils.class)) {
            mockedFileUtils.when(FileUtils::getFido2Home).thenReturn(fido2Home);
            mockedFileUtils.when(() -> FileUtils.getStashFile(Mockito.any(File.class))).thenCallRealMethod();
            mockedFileUtils.when(() -> FileUtils.readFileBytes(Mockito.any(File.class))).thenCallRealMethod();
            
            // Set up input for the scanner
            String simulatedUserInput =
                "\n" +
                "\n" +             // Accept default passkey file
                "testpassword123\n";  // PIN (at least 8 characters)
                
            System.setIn(new ByteArrayInputStream(simulatedUserInput.getBytes()));
            
            // Set the root key pair
            setRootKeyPair(rootKeyPair.getPublic(), rootKeyPair.getPrivate());
            
            // Call the main method with 'generate' command
            Passkey.main(new String[]{"generate"});
            logOutErr();
            // Verify output contains success message
            String output = outContent.toString();
            originalErr.println(output);
            assertTrue("Output should indicate successful generation",
                      output.contains("Passkey successfully generated"));
            
            // Verify the passkey file was created
            File passkeyFile = new File(fido2Home + File.separator + "default.passkey");
            assertTrue("Passkey file should exist", passkeyFile.exists());
            assertTrue("Passkey file should have content", passkeyFile.length() > 0);
            
            // Verify the companion stash file was also created
            File stashFile = FileUtils.getStashFile(passkeyFile);
            assertTrue("Stash file should exist", stashFile.exists());
            assertTrue("Stash file should have content", stashFile.length() > 0);
        }
    }
    
    /**
     * Test the main method with 'manage' command
     */
    @Test
    public void testMainWithManageCommand() throws Exception {
        originalErr.println("testMainWithManageCommand");
        // First generate a passkey to manage
        File passkeyFile;
        String passkeyName;
        
        // Mock FileUtils.getFido2Home() to return our temporary directory
        try (MockedStatic<FileUtils> mockedFileUtils = Mockito.mockStatic(FileUtils.class)) {
            mockedFileUtils.when(FileUtils::getFido2Home).thenReturn(fido2Home);
            // Allow readFileBytes and getStashFile to call the real implementation
            mockedFileUtils.when(() -> FileUtils.readFileBytes(Mockito.any(File.class)))
                .thenCallRealMethod();
            mockedFileUtils.when(() -> FileUtils.getStashFile(Mockito.any(File.class)))
                .thenCallRealMethod();
            
            // Initialize root key pair within mock scope so rootPublicKey is set
            Passkey.ensureRootKeyPair(null, null);
            
            // Create a passkey file first with a unique name
            passkeyFile = getUniquePasskeyFile("manage_test");
            passkeyName = passkeyFile.getName();
            byte[] pinHash = KeyUtils.getPinHash("testpassword123");
            Passkey passkey = Passkey.generatePasskey(pinHash, passkeyFile);
            assertNotNull("Generated passkey should not be null", passkey);
            assertTrue("Passkey file should exist", passkeyFile.exists());
            assertTrue("Passkey file should have content", passkeyFile.length() > 0);
            logOutErr();
            // Clear the output streams
            originalErr.println("testMainWithManageCommand read test start");
            originalErr.println("Passkey file size: " + passkeyFile.length());
            outContent.reset();
            errContent.reset();
            
            // Set up input for the scanner
            String simulatedUserInput =
                "\n" +             // Accept default platform key
                passkeyName + "\n" +  // Generated passkey file
                "testpassword123\n";  // PIN
                
            System.setIn(new ByteArrayInputStream(simulatedUserInput.getBytes()));
            
            // Call the main method with 'manage' command - must be within mock scope
            // Note: rootKeyPair was already set by ensureRootKeyPair() at line 168
            Passkey.main(new String[]{"manage"});
            logOutErr();

            // Verify output contains success message
            String output = outContent.toString();
            assertTrue("Output should indicate successful opening",
                      output.contains("Passkey successfully opened"));
        }
    }
    
    /**
     * Test the main method with invalid command
     */
    @Test
    public void testMainWithInvalidCommand() {
        originalErr.println("testMainWithInvalidCommand");
        // Call the main method with an invalid command
        String in = " ";
        System.setIn(new ByteArrayInputStream(in.getBytes()));
        Passkey.main(new String[]{"invalid"});
        logOutErr();
        // Verify output contains usage message
        String output = outContent.toString();
        assertTrue("Output should contain usage message", 
                  output.contains("Usage:"));
    }
    
    /**
     * Test the main method with no arguments
     */
    @Test
    public void testMainWithNoArguments() {
        originalErr.println("testMainWithNoArguments");
        // Call the main method with no arguments
        Passkey.main(new String[]{});
        
        // Verify output contains usage message
        String output = outContent.toString();
        assertTrue("Output should contain usage message", 
                  output.contains("Usage:"));
    }
    
    /**
     * Test the main method with exception handling
     */
    @Test
    public void testMainWithException() throws Exception {
        originalErr.println("testMainWithException");
        // Mock FileUtils.getFido2Home() to throw an exception
        try (MockedStatic<FileUtils> mockedFileUtils = Mockito.mockStatic(FileUtils.class)) {
            mockedFileUtils.when(FileUtils::getFido2Home).thenThrow(new RuntimeException("Test exception"));
            mockedFileUtils.when(() -> FileUtils.getStashFile(Mockito.any(File.class))).thenCallRealMethod();
            mockedFileUtils.when(() -> FileUtils.readFileBytes(Mockito.any(File.class))).thenCallRealMethod();
            
            // Set up input for the scanner
            String simulatedUserInput = 
                "\n" +             // Accept default platform key
                "\n" +             // Accept default passkey file
                "testpassword123\n";  // PIN
                
            System.setIn(new ByteArrayInputStream(simulatedUserInput.getBytes()));
            
            // Call the main method with 'generate' command
            Passkey.main(new String[]{"generate"});
            logOutErr();
            // Verify error output contains exception message
            String errorOutput = errContent.toString();
            assertTrue("Error output should contain exception message :: " + errorOutput, 
                      errorOutput.contains("Test exception"));
        }
    }
    
    /**
     * Test the main method with invalid PIN (too short)
     */
    @Test
    public void testMainWithInvalidPin() throws Exception {
        originalErr.println("testMainWithInvalidPin");
        // Mock FileUtils.getFido2Home() to return our temporary directory
        try (MockedStatic<FileUtils> mockedFileUtils = Mockito.mockStatic(FileUtils.class)) {
            mockedFileUtils.when(FileUtils::getFido2Home).thenReturn(fido2Home);
            mockedFileUtils.when(() -> FileUtils.getStashFile(Mockito.any(File.class))).thenCallRealMethod();
            mockedFileUtils.when(() -> FileUtils.readFileBytes(Mockito.any(File.class))).thenCallRealMethod();
            
            // Set up input for the scanner with a PIN that's too short
            String simulatedUserInput = 
                "\n" +      // Accept default platform key
                "\n" +      // Accept default passkey file
                "short\n";  // PIN (less than 8 characters)
                
            System.setIn(new ByteArrayInputStream(simulatedUserInput.getBytes()));
            
            // Set the root key pair
            setRootKeyPair(rootKeyPair.getPublic(), rootKeyPair.getPrivate());
            
            // Call the main method with 'generate' command
            Passkey.main(new String[]{"generate"});
            logOutErr();
            // Verify output contains error message
            String output = outContent.toString();
            assertTrue("Output should indicate PIN error", 
                      output.contains("PIN must be at least 8 characters"));
            
            // Verify the passkey file was not created
            File passkeyFile = new File(fido2Home + File.separator + "default.passkey");
            assertFalse("Passkey file should not exist with invalid PIN", passkeyFile.exists());
            
            // Also verify the error message in the output
            assertTrue("Output should contain PIN error message",
                      output.contains("PIN must be at least 8 characters"));
        }
    }
    
    /**
     * Test the main method with file overwrite confirmation
     */
    @Test
    public void testMainWithFileOverwriteConfirmation() throws Exception {
        originalErr.println("testMainWithFileOverwriteConfirmation");
        // Mock FileUtils.getFido2Home() to return our temporary directory
        try (MockedStatic<FileUtils> mockedFileUtils = Mockito.mockStatic(FileUtils.class)) {
            mockedFileUtils.when(FileUtils::getFido2Home).thenReturn(fido2Home);
            mockedFileUtils.when(() -> FileUtils.getStashFile(Mockito.any(File.class))).thenCallRealMethod();
            mockedFileUtils.when(() -> FileUtils.readFileBytes(Mockito.any(File.class))).thenCallRealMethod();
            
            // Create a passkey file first with a unique name
            File passkeyFile = getUniquePasskeyFile("overwrite_test");
            passkeyFile.createNewFile(); // Just create an empty file
            
            // Set up input for the scanner with confirmation to overwrite
            String simulatedUserInput = 
                "\n" +             // Accept default platform key
                passkeyFile.getName() + "\n" + // Generated passkey file
                "y\n" +            // Confirm overwrite
                "testpassword123\n";  // PIN
                
            System.setIn(new ByteArrayInputStream(simulatedUserInput.getBytes()));
            
            // Set the root key pair
            setRootKeyPair(rootKeyPair.getPublic(), rootKeyPair.getPrivate());
            
            // Call the main method with 'generate' command
            Passkey.main(new String[]{"generate"});
            logOutErr();
            // Verify output contains success message
            String output = outContent.toString();
            assertTrue("Output should indicate successful generation", 
                      output.contains("Passkey successfully generated"));
        }
    }
    
    /**
     * Test the main method with file overwrite rejection
     */
    @Test
    public void testMainWithFileOverwriteRejection() throws Exception {
        originalErr.println("testMainWithFileOverwriteRejection");
        // Mock FileUtils.getFido2Home() to return our temporary directory
        try (MockedStatic<FileUtils> mockedFileUtils = Mockito.mockStatic(FileUtils.class)) {
            mockedFileUtils.when(FileUtils::getFido2Home).thenReturn(fido2Home);
            mockedFileUtils.when(() -> FileUtils.getStashFile(Mockito.any(File.class))).thenCallRealMethod();
            mockedFileUtils.when(() -> FileUtils.readFileBytes(Mockito.any(File.class))).thenCallRealMethod();
            
            // Create a passkey file first
            File passkeyFile = getUniquePasskeyFile("reject_test");
            passkeyFile.createNewFile(); // Just create an empty file
            long originalModified = passkeyFile.lastModified();
            
            // Set up input for the scanner with rejection of overwrite
            String simulatedUserInput = 
                "\n" +             // Accept default platform key
                passkeyFile.getName() + "\n" +  // Generated passkey file
                "n\n";             // Reject overwrite
                
            System.setIn(new ByteArrayInputStream(simulatedUserInput.getBytes()));
            
            // Set the root key pair
            setRootKeyPair(rootKeyPair.getPublic(), rootKeyPair.getPrivate());
            
            // Call the main method with 'generate' command
            Passkey.main(new String[]{"generate"});
            logOutErr();
            // Verify output contains cancellation message
            String output = outContent.toString();
            assertTrue("Output should indicate operation cancelled", 
                      output.contains("Operation cancelled"));
            
            // Verify the file wasn't modified
            assertEquals("File should not be modified", originalModified, passkeyFile.lastModified());
        }
    }
    
    /**
     * Test the main method with custom passkey file name
     */
    @Test
    public void testMainWithCustomPasskeyFileName() throws Exception {
        originalErr.println("testMainWithCustomPasskeyFileName");
        // Mock FileUtils.getFido2Home() to return our temporary directory
        try (MockedStatic<FileUtils> mockedFileUtils = Mockito.mockStatic(FileUtils.class)) {
            mockedFileUtils.when(FileUtils::getFido2Home).thenReturn(fido2Home);
            mockedFileUtils.when(() -> FileUtils.getStashFile(Mockito.any(File.class))).thenCallRealMethod();
            mockedFileUtils.when(() -> FileUtils.readFileBytes(Mockito.any(File.class))).thenCallRealMethod();
            
            // Set up input for the scanner with custom file name
            String simulatedUserInput = 
                "\n" + 
                "custom_file\n" +       // Custom file name (will have .passkey appended)
                "testpassword123\n";    // PIN
                
            System.setIn(new ByteArrayInputStream(simulatedUserInput.getBytes()));
            
            // Set the root key pair
            setRootKeyPair(rootKeyPair.getPublic(), rootKeyPair.getPrivate());
            
            // Call the main method with 'generate' command
            Passkey.main(new String[]{"generate"});
            logOutErr();
            // Verify output contains success message
            String output = outContent.toString();
            assertTrue("Output should indicate successful generation", 
                      output.contains("Passkey successfully generated"));
            
            // Verify the custom passkey file was created
            File passkeyFile = new File(fido2Home + File.separator + "custom_file.passkey");
            assertTrue("Custom passkey file should exist", passkeyFile.exists());
            assertTrue("Custom passkey file should have content", passkeyFile.length() > 0);
        }
    }
}

// Made with Bob

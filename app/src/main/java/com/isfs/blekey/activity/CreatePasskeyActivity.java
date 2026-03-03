package com.isfs.blekey.activity;

import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.isfs.blekey.R;
import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.util.AndroidKeystoreManager;
import com.isfs.blekey.util.KeyUtils;

import java.io.File;
import java.util.regex.Pattern;

/**
 * Activity for creating a new passkey.
 * This activity allows users to create a new passkey by providing a name
 * and password. The passkey name is used as the filename and must contain only
 * alphanumeric characters. The password must be at least 8 characters long.
 */
public class CreatePasskeyActivity extends AppCompatActivity {

    private EditText passkeyNameInput;
    private EditText passwordInput;
    private EditText confirmPasswordInput;
    private Button createButton;
    private TextView nameErrorText;
    private TextView passwordErrorText;

    // Pattern for validating passkey name (alphanumeric only)
    private static final Pattern NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9]+$");
    private static final int MIN_PASSWORD_LENGTH = 8;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_create_passkey);

        // Initialize UI components
        passkeyNameInput = findViewById(R.id.createPasskeyNameInput);
        passwordInput = findViewById(R.id.createPasskeyPasswordInput);
        confirmPasswordInput = findViewById(R.id.confirmPasswordInput);
        createButton = findViewById(R.id.createPasskeyButton);
        nameErrorText = findViewById(R.id.nameErrorText);
        passwordErrorText = findViewById(R.id.passwordErrorText);

        // Set up input validation
        setupInputValidation();

        // Set up create button click listener
        createButton.setOnClickListener(view -> createPasskey());

        // Set up back button in toolbar
        findViewById(R.id.backButton).setOnClickListener(view -> finish());
    }

    /**
     * Sets up input validation for the local name and password fields.
     */
    private void setupInputValidation() {
        // Validate local name (alphanumeric only)
        passkeyNameInput.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                // Not used
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                validateInputs();
            }

            @Override
            public void afterTextChanged(Editable s) {
                // Not used
            }
        });

        // Validate password (minimum 8 characters)
        TextWatcher passwordWatcher = new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                // Not used
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                validateInputs();
            }

            @Override
            public void afterTextChanged(Editable s) {
                // Not used
            }
        };

        passwordInput.addTextChangedListener(passwordWatcher);
        confirmPasswordInput.addTextChangedListener(passwordWatcher);
    }

    /**
     * Validates the inputs and updates the UI accordingly.
     * Enables the create button only if all inputs are valid.
     */
    private void validateInputs() {
        boolean isValid = true;
        String localName = passkeyNameInput.getText().toString().trim();
        String password = passwordInput.getText().toString();
        String confirmPassword = confirmPasswordInput.getText().toString();

        // Validate local name
        if (localName.isEmpty()) {
            nameErrorText.setText(R.string.prompt_passkey_name);
            nameErrorText.setVisibility(View.VISIBLE);
            isValid = false;
        } else if (!NAME_PATTERN.matcher(localName).matches()) {
            nameErrorText.setText(R.string.prompt_passkey_help);
            nameErrorText.setVisibility(View.VISIBLE);
            isValid = false;
        } else {
            nameErrorText.setVisibility(View.GONE);
        }

        // Validate password
        if (password.isEmpty()) {
            passwordErrorText.setText(R.string.require_password);
            passwordErrorText.setVisibility(View.VISIBLE);
            isValid = false;
        } else if (password.length() < MIN_PASSWORD_LENGTH) {
            passwordErrorText.setText(R.string.password_length_policy);
            passwordErrorText.setVisibility(View.VISIBLE);
            isValid = false;
        } else if (!password.equals(confirmPassword)) {
            passwordErrorText.setText(R.string.password_verify_policy);
            passwordErrorText.setVisibility(View.VISIBLE);
            isValid = false;
        } else {
            passwordErrorText.setVisibility(View.GONE);
        }

        // Enable/disable create button
        createButton.setEnabled(isValid);
    }

    /**
     * Creates a new passkey with the provided local name and password.
     */
    private void createPasskey() {
        String passkeyName = passkeyNameInput.getText().toString().trim();
        String password = passwordInput.getText().toString();

        // Generate passkey file path
        File passkeyFile = new File(getFilesDir(), passkeyName + ".passkey");

        // Check if file already exists
        if (passkeyFile.exists()) {
            Toast.makeText(this, getString(R.string.passkey_exists_error), Toast.LENGTH_SHORT).show();
            return;
        }

        // Ensure FIDO2_HOME is set correctly
        String fido2Home = System.getProperty("FIDO2_HOME");
        if (fido2Home == null) {
            fido2Home = getFilesDir().getAbsolutePath();
            System.setProperty("FIDO2_HOME", fido2Home);
        }

        // Ensure KeystoreManager is initialized (guards against cold-start without MainActivity)
        Passkey.setKeystoreManager(new AndroidKeystoreManager());

        // Generate PIN hash from password
        byte[] pinHash = KeyUtils.getPinHash(password);

        // Generate passkey
        Passkey passkey = Passkey.generatePasskey(pinHash, passkeyFile);

        if (passkey != null) {
            Toast.makeText(this, R.string.create_passkey_success, Toast.LENGTH_SHORT).show();
            finish(); // Return to previous activity
        } else {
            Toast.makeText(this, R.string.create_passkey_fail, Toast.LENGTH_SHORT).show();
        }
    }
}

// Made with Bob

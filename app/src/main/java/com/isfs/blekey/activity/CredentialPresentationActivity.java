package com.isfs.blekey.activity;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.isfs.blekey.R;
import com.isfs.blekey.credential.VerifiableCredential;
import com.isfs.blekey.data.Passkey;
import com.isfs.blekey.oidc.Oidc4VpHandler;
import com.isfs.blekey.oidc.OidcException;
import com.isfs.blekey.oidc.PresentationDefinition;
import com.isfs.blekey.util.AndroidHolderBindingKeyManager;
import com.isfs.blekey.util.BiometricAuthHelper;

import java.io.File;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Activity for handling credential presentation requests.
 * Displays presentation request details and manages the presentation flow.
 */
public class CredentialPresentationActivity extends AppCompatActivity {
    
    private static final String TAG = CredentialPresentationActivity.class.getCanonicalName();
    
    private TextView verifierNameText;
    private TextView requestedClaimsText;
    private RecyclerView matchedCredentialsRecyclerView;
    private TextView noMatchingCredentialsText;
    private LinearLayout selectiveDisclosureContainer;
    private TextView selectiveDisclosureLabel;
    private Button shareButton;
    private Button cancelButton;
    private ProgressBar progressBar;
    private View contentLayout;
    
    private String presentationRequestUri;
    private PresentationDefinition presentationDefinition;
    private List<VerifiableCredential> matchedCredentials;
    private VerifiableCredential selectedCredential;
    private Map<String, Boolean> selectedClaims;
    private byte[] passwordHash;
    private String passkeyFileName;
    
    private final ExecutorService executorService = Executors.newSingleThreadExecutor();
    private BiometricAuthHelper biometricAuthHelper;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_credential_presentation);
        
        findViewById(R.id.backButton).setOnClickListener(view -> finish());
        
        // Set up home button to navigate to MainActivity
        findViewById(R.id.homeButton).setOnClickListener(view -> {
            Intent intent = new Intent(this, com.isfs.blekey.MainActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(intent);
            finish();
        });
        
        initializeViews();
        
        biometricAuthHelper = new BiometricAuthHelper(this);
        
        Intent intent = getIntent();
        if (intent != null) {
            presentationRequestUri = intent.getStringExtra("presentation_request_uri");
            passwordHash = intent.getByteArrayExtra("passkey");
            passkeyFileName = intent.getStringExtra("file");
        }
        
        if (presentationRequestUri != null) {
            fetchPresentationRequest();
        } else {
            showError("No presentation request provided");
        }
    }
    
    private void initializeViews() {
        verifierNameText = findViewById(R.id.verifierName);
        requestedClaimsText = findViewById(R.id.requestedClaims);
        matchedCredentialsRecyclerView = findViewById(R.id.matchedCredentialsRecyclerView);
        noMatchingCredentialsText = findViewById(R.id.noMatchingCredentials);
        selectiveDisclosureContainer = findViewById(R.id.selectiveDisclosureContainer);
        selectiveDisclosureLabel = findViewById(R.id.selectiveDisclosureLabel);
        shareButton = findViewById(R.id.shareButton);
        cancelButton = findViewById(R.id.cancelButton);
        progressBar = findViewById(R.id.progressBar);
        contentLayout = findViewById(R.id.contentLayout);
        
        matchedCredentialsRecyclerView.setLayoutManager(new LinearLayoutManager(this));
        
        shareButton.setOnClickListener(v -> shareCredential());
        cancelButton.setOnClickListener(v -> cancelPresentation());
        
        selectedClaims = new HashMap<>();
    }
    
    private void fetchPresentationRequest() {
        showProgress(true);
        
        executorService.execute(() -> {
            try {
                presentationDefinition = PresentationDefinition.fromUri(presentationRequestUri);
                
                if (passwordHash != null && passkeyFileName != null) {
                    File appDataDir = getFilesDir();
                    System.setProperty("FIDO2_HOME", appDataDir.getAbsolutePath());
                    
                    File passkeyFile = new File(appDataDir, passkeyFileName);
                    Passkey passkey = Passkey.openKey(passwordHash, passkeyFile);
                    
                    if (passkey != null) {
                        matchedCredentials = matchCredentials(passkey.getVerifiableCredentials());
                    }
                }
                
                runOnUiThread(this::displayPresentationRequest);
            } catch (OidcException e) {
                Log.e(TAG, "Failed to fetch presentation request", e);
                runOnUiThread(() -> showError("Failed to fetch presentation request: " + e.getMessage()));
            } catch (Exception e) {
                Log.e(TAG, "Error processing presentation request", e);
                runOnUiThread(() -> showError("Error processing presentation request: " + e.getMessage()));
            }
        });
    }
    
    private List<VerifiableCredential> matchCredentials(List<VerifiableCredential> credentials) {
        if (credentials == null || credentials.isEmpty()) {
            return new ArrayList<>();
        }
        
        List<VerifiableCredential> matched = new ArrayList<>();
        for (VerifiableCredential vc : credentials) {
            if (presentationDefinition.matches(vc)) {
                matched.add(vc);
            }
        }
        
        return matched;
    }
    
    private void displayPresentationRequest() {
        showProgress(false);
        
        if (presentationDefinition != null) {
            verifierNameText.setText(presentationDefinition.getVerifierName());
            
            List<String> requestedFields = presentationDefinition.getRequestedFields();
            if (requestedFields != null && !requestedFields.isEmpty()) {
                requestedClaimsText.setText(String.join(", ", requestedFields));
            } else {
                requestedClaimsText.setText("All available claims");
            }
        }
        
        if (matchedCredentials != null && !matchedCredentials.isEmpty()) {
            CredentialAdapter adapter = new CredentialAdapter(matchedCredentials);
            matchedCredentialsRecyclerView.setAdapter(adapter);
            matchedCredentialsRecyclerView.setVisibility(View.VISIBLE);
            noMatchingCredentialsText.setVisibility(View.GONE);
            
            if (matchedCredentials.size() == 1) {
                selectedCredential = matchedCredentials.get(0);
                setupSelectiveDisclosure();
            }
        } else {
            matchedCredentialsRecyclerView.setVisibility(View.GONE);
            noMatchingCredentialsText.setVisibility(View.VISIBLE);
            shareButton.setEnabled(false);
        }
    }
    
    private void setupSelectiveDisclosure() {
        if (selectedCredential == null || presentationDefinition == null) {
            return;
        }
        
        List<String> requestedFields = presentationDefinition.getRequestedFields();
        if (requestedFields == null || requestedFields.isEmpty()) {
            return;
        }
        
        selectiveDisclosureLabel.setVisibility(View.VISIBLE);
        selectiveDisclosureContainer.setVisibility(View.VISIBLE);
        selectiveDisclosureContainer.removeAllViews();
        
        for (String field : requestedFields) {
            CheckBox checkBox = new CheckBox(this);
            checkBox.setText(field);
            checkBox.setChecked(true);
            checkBox.setOnCheckedChangeListener((buttonView, isChecked) -> 
                selectedClaims.put(field, isChecked)
            );
            
            selectedClaims.put(field, true);
            selectiveDisclosureContainer.addView(checkBox);
        }
    }
    
    private void shareCredential() {
        if (selectedCredential == null) {
            Toast.makeText(this, "No credential selected", Toast.LENGTH_SHORT).show();
            return;
        }
        
        biometricAuthHelper.authenticateForPresentation(new BiometricAuthHelper.AuthenticationCallback() {
            @Override
            public void onAuthenticationSucceeded() {
                performPresentation();
            }
            
            @Override
            public void onAuthenticationFailed(String errorMessage) {
                Toast.makeText(CredentialPresentationActivity.this, 
                    R.string.authentication_required, Toast.LENGTH_LONG).show();
            }
            
            @Override
            public void onAuthenticationCancelled() {
                Toast.makeText(CredentialPresentationActivity.this, 
                    "Authentication cancelled", Toast.LENGTH_SHORT).show();
            }
        });
    }
    
    private void performPresentation() {
        showProgress(true);
        shareButton.setEnabled(false);
        cancelButton.setEnabled(false);
        
        executorService.execute(() -> {
            try {
                PrivateKey holderBindingKey = AndroidHolderBindingKeyManager.deriveHolderBindingKey(
                    selectedCredential.getHolderBindingKeySeed(),
                    selectedCredential.getSalt(),
                    selectedCredential.getMetadata().getIssuerDid(),
                    selectedCredential.getMetadata().getCredentialType()
                );
                
                Oidc4VpHandler vpHandler = new Oidc4VpHandler();
                
                List<String> disclosedClaims = new ArrayList<>();
                for (Map.Entry<String, Boolean> entry : selectedClaims.entrySet()) {
                    if (entry.getValue()) {
                        disclosedClaims.add(entry.getKey());
                    }
                }
                
                String vpToken = vpHandler.createPresentation(
                    selectedCredential,
                    holderBindingKey,
                    presentationDefinition,
                    disclosedClaims
                );
                
                boolean submitted = vpHandler.submitPresentation(
                    presentationRequestUri,
                    vpToken
                );
                
                if (submitted) {
                    runOnUiThread(this::showSuccess);
                } else {
                    runOnUiThread(() -> showError("Failed to submit presentation"));
                }
                
            } catch (Exception e) {
                Log.e(TAG, "Failed to create presentation", e);
                runOnUiThread(() -> showError("Failed to create presentation: " + e.getMessage()));
            }
        });
    }
    
    private void cancelPresentation() {
        Toast.makeText(this, "Presentation cancelled", Toast.LENGTH_SHORT).show();
        finish();
    }
    
    private void showProgress(boolean show) {
        progressBar.setVisibility(show ? View.VISIBLE : View.GONE);
        contentLayout.setVisibility(show ? View.GONE : View.VISIBLE);
    }
    
    private void showError(String message) {
        showProgress(false);
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
        shareButton.setEnabled(false);
    }
    
    private void showSuccess() {
        showProgress(false);
        Toast.makeText(this, R.string.presentation_success, Toast.LENGTH_LONG).show();
        finish();
    }
    
    @Override
    protected void onDestroy() {
        super.onDestroy();
        executorService.shutdown();
    }
    
    /**
     * Adapter for displaying matched credentials
     */
    private class CredentialAdapter extends RecyclerView.Adapter<CredentialAdapter.ViewHolder> {
        
        private final List<VerifiableCredential> credentials;
        
        CredentialAdapter(List<VerifiableCredential> credentials) {
            this.credentials = credentials;
        }
        
        @NonNull
        @Override
        public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.digital_credential_list_item, parent, false);
            return new ViewHolder(view);
        }
        
        @Override
        public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
            VerifiableCredential vc = credentials.get(position);
            
            String credType = vc.getMetadata().getCredentialType();
            holder.credentialType.setText(credType != null ? credType : "Digital Credential");
            
            String issuer = vc.getMetadata().getIssuerDid();
            if (issuer == null) {
                issuer = vc.getMetadata().getIssuerUrl();
            }
            holder.issuerName.setText(issuer != null ? issuer : "Unknown Issuer");
            
            holder.statusIndicator.setText(R.string.credential_valid);
            holder.statusIndicator.setTextColor(0xFF4CAF50);
            
            holder.itemView.setOnClickListener(v -> {
                selectedCredential = vc;
                setupSelectiveDisclosure();
                notifyDataSetChanged();
            });
            
            if (vc.equals(selectedCredential)) {
                holder.itemView.setBackgroundColor(0xFFE3F2FD);
            } else {
                holder.itemView.setBackgroundColor(0xFFFFFFFF);
            }
        }
        
        @Override
        public int getItemCount() {
            return credentials.size();
        }
        
        class ViewHolder extends RecyclerView.ViewHolder {
            TextView credentialType;
            TextView issuerName;
            TextView statusIndicator;
            
            ViewHolder(View view) {
                super(view);
                credentialType = view.findViewById(R.id.credentialType);
                issuerName = view.findViewById(R.id.issuerName);
                statusIndicator = view.findViewById(R.id.statusIndicator);
            }
        }
    }
}

// Made with Bob
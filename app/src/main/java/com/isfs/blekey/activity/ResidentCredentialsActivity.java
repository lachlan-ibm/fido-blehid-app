package com.isfs.blekey.activity;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import androidx.viewpager2.adapter.FragmentStateAdapter;
import androidx.viewpager2.widget.ViewPager2;

import com.google.android.material.tabs.TabLayout;
import com.google.android.material.tabs.TabLayoutMediator;
import com.isfs.blekey.R;
import com.isfs.blekey.credential.VerifiableCredential;
import com.isfs.blekey.data.Passkey;

import android.widget.FrameLayout;
import android.widget.Toast;
import android.widget.ImageView;

import java.io.File;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Activity for managing resident credentials and digital credentials stored on the device.
 * This activity displays tabs for switching between FIDO2 passkeys and digital credentials.
 */
public class ResidentCredentialsActivity extends AppCompatActivity {
    
    private static final String TAG = ResidentCredentialsActivity.class.getCanonicalName();
    
    private byte[] passwordHash;
    private String fileName;
    private Passkey passkey;
    
    private TabLayout tabLayout;
    private ViewPager2 viewPager;
    private FrameLayout loadingFrame;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_resident_credentials);

        Intent intent = getIntent();
        if (intent != null) {
            passwordHash = intent.getByteArrayExtra("passkey");
            fileName = intent.getStringExtra("file");
        }

        findViewById(R.id.backButton).setOnClickListener(view -> finish());

        // Set up home button to navigate to MainActivity
        findViewById(R.id.homeButton).setOnClickListener(view -> {
            Intent homeIntent = new Intent(this, com.isfs.blekey.MainActivity.class);
            homeIntent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(homeIntent);
            finish();
        });

        tabLayout = findViewById(R.id.tabLayout);
        viewPager = findViewById(R.id.viewPager);
        loadingFrame = findViewById(R.id.loadingFrame);

        // Hide tabs until passkey is loaded; loadPasskey() calls setupTabs() on completion
        tabLayout.setVisibility(View.GONE);
        viewPager.setVisibility(View.GONE);
        loadPasskey();
    }

    private void loadPasskey() {
        if (fileName == null || passwordHash == null) {
            Toast.makeText(this, "Failed to open passkey", Toast.LENGTH_SHORT).show();
            return;
        }

        loadingFrame.setVisibility(View.VISIBLE);

        ExecutorService exec = Executors.newSingleThreadExecutor();
        exec.execute(() -> {
            Passkey loaded = null;
            try {
                File appDataDir = getFilesDir();
                System.setProperty("FIDO2_HOME", appDataDir.getAbsolutePath());
                loaded = Passkey.openKey(passwordHash, new File(appDataDir, fileName));
            } catch (Exception e) {
                Log.e(TAG, "Error loading passkey", e);
            }

            final Passkey result = loaded;
            runOnUiThread(() -> {
                loadingFrame.setVisibility(View.GONE);
                if (result == null) {
                    Log.e(TAG, "Failed to open passkey");
                    Toast.makeText(this, "Failed to open passkey", Toast.LENGTH_SHORT).show();
                } else {
                    passkey = result;
                    tabLayout.setVisibility(View.VISIBLE);
                    viewPager.setVisibility(View.VISIBLE);
                    setupTabs();
                }
            });
            exec.shutdown();
        });
    }
    
    private void setupTabs() {
        CredentialsPagerAdapter pagerAdapter = new CredentialsPagerAdapter(this);
        viewPager.setAdapter(pagerAdapter);
        
        new TabLayoutMediator(tabLayout, viewPager, (tab, position) -> {
            switch (position) {
                case 0:
                    tab.setText(R.string.tab_passkeys);
                    break;
                case 1:
                    tab.setText(R.string.tab_digital_credentials);
                    break;
            }
        }).attach();
    }
    
    /**
     * ViewPager adapter for managing tabs
     */
    private class CredentialsPagerAdapter extends FragmentStateAdapter {
        
        public CredentialsPagerAdapter(@NonNull FragmentActivity fragmentActivity) {
            super(fragmentActivity);
        }
        
        @NonNull
        @Override
        public Fragment createFragment(int position) {
            switch (position) {
                case 0:
                    return new PasskeysFragment();
                case 1:
                    return new DigitalCredentialsFragment();
                default:
                    return new PasskeysFragment();
            }
        }
        
        @Override
        public int getItemCount() {
            return 2;
        }
    }
    
    /**
     * Fragment for displaying FIDO2 passkeys
     */
    public static class PasskeysFragment extends Fragment {
        
        private RecyclerView recyclerView;
        private View emptyStateView;
        private PasskeyAdapter adapter;
        
        @Override
        public View onCreateView(@NonNull LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
            View view = inflater.inflate(R.layout.passkeys_tab, container, false);
            
            recyclerView = view.findViewById(R.id.digitalCredentialsRecyclerView);
            emptyStateView = view.findViewById(R.id.emptyStateView);
            SwipeRefreshLayout swipeRefresh = view.findViewById(R.id.swipeRefreshLayout);
            swipeRefresh.setEnabled(false);
            
            recyclerView.setLayoutManager(new LinearLayoutManager(getContext()));
            
            loadPasskeys();
            
            return view;
        }
        
        private void loadPasskeys() {
            ResidentCredentialsActivity activity = (ResidentCredentialsActivity) getActivity();
            if (activity == null || activity.passkey == null) {
                showEmptyState();
                return;
            }
            
            List<Map<String, byte[]>> resCreds = activity.passkey.getResCreds();
            if (resCreds == null || resCreds.isEmpty()) {
                showEmptyState();
                return;
            }
            
            adapter = new PasskeyAdapter(resCreds, activity);
            recyclerView.setAdapter(adapter);
            recyclerView.setVisibility(View.VISIBLE);
            emptyStateView.setVisibility(View.GONE);
        }
        
        private void showEmptyState() {
            recyclerView.setVisibility(View.GONE);
            emptyStateView.setVisibility(View.VISIBLE);
        }
    }
    
    /**
     * Fragment for displaying digital credentials
     */
    public static class DigitalCredentialsFragment extends Fragment {
        
        private RecyclerView recyclerView;
        private View emptyStateView;
        private DigitalCredentialAdapter adapter;
        private SwipeRefreshLayout swipeRefresh;
        
        @Override
        public View onCreateView(@NonNull LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
            View view = inflater.inflate(R.layout.digital_credentials_tab, container, false);
            
            recyclerView = view.findViewById(R.id.digitalCredentialsRecyclerView);
            emptyStateView = view.findViewById(R.id.emptyStateView);
            swipeRefresh = view.findViewById(R.id.swipeRefreshLayout);
            
            recyclerView.setLayoutManager(new LinearLayoutManager(getContext()));
            
            swipeRefresh.setOnRefreshListener(this::refreshCredentials);
            
            loadDigitalCredentials();
            
            return view;
        }
        
        private void loadDigitalCredentials() {
            ResidentCredentialsActivity activity = (ResidentCredentialsActivity) getActivity();
            if (activity == null || activity.passkey == null) {
                showEmptyState();
                return;
            }
            
            List<VerifiableCredential> vcs = activity.passkey.getVerifiableCredentials();
            if (vcs == null || vcs.isEmpty()) {
                showEmptyState();
                return;
            }
            
            adapter = new DigitalCredentialAdapter(vcs, activity);
            recyclerView.setAdapter(adapter);
            recyclerView.setVisibility(View.VISIBLE);
            emptyStateView.setVisibility(View.GONE);
        }
        
        private void refreshCredentials() {
            swipeRefresh.setRefreshing(false);
            Toast.makeText(getContext(), "Status refresh not yet implemented", Toast.LENGTH_SHORT).show();
        }
        
        private void showEmptyState() {
            recyclerView.setVisibility(View.GONE);
            emptyStateView.setVisibility(View.VISIBLE);
        }
    }
    
    /**
     * Adapter for FIDO2 passkeys
     */
    private static class PasskeyAdapter extends RecyclerView.Adapter<PasskeyAdapter.ViewHolder> {
        
        private final List<Map<String, byte[]>> passkeys;
        private final ResidentCredentialsActivity activity;
        
        PasskeyAdapter(List<Map<String, byte[]>> passkeys, ResidentCredentialsActivity activity) {
            this.passkeys = passkeys;
            this.activity = activity;
        }
        
        @NonNull
        @Override
        public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(parent.getContext())
                    .inflate(android.R.layout.simple_list_item_2, parent, false);
            return new ViewHolder(view);
        }
        
        @Override
        public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
            Map<String, byte[]> cred = passkeys.get(position);
            try {
                String rpId = new String(cred.get("rp.id"), "UTF-8");
                holder.text1.setText("Credential: " + rpId);
                
                // Display user_handle as hex (first 16 bytes, or 13 + "..." if longer)
                byte[] userHandle = cred.get("user.id");
                String userHandleDisplay = formatUserHandle(userHandle);
                holder.text2.setText("User: " + userHandleDisplay);
                
                holder.itemView.setOnClickListener(v -> showDeleteDialog(cred.get("rp.id"), rpId));
            } catch (Exception e) {
                holder.text1.setText("Credential: [Encoding Error]");
                holder.text2.setText("");
            }
        }
        
        /**
         * Formats a user handle as hex string.
         * Shows first 16 bytes, or first 13 bytes + "..." if longer.
         *
         * @param userHandle The user handle byte array
         * @return Formatted hex string
         */
        private String formatUserHandle(byte[] userHandle) {
            if (userHandle == null || userHandle.length == 0) {
                return "(empty)";
            }
            
            // Determine how many bytes to show
            int bytesToShow = Math.min(userHandle.length, 16);
            boolean truncated = userHandle.length > 16;
            
            if (truncated) {
                bytesToShow = 13; // Show 13 bytes + "..." if truncated
            }
            
            // Convert to hex
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < bytesToShow; i++) {
                hex.append(String.format("%02x", userHandle[i]));
            }
            
            if (truncated) {
                hex.append("...");
            }
            
            return hex.toString();
        }
        
        @Override
        public int getItemCount() {
            return passkeys.size();
        }
        
        private void showDeleteDialog(byte[] rpId, String rpIdStr) {
            new AlertDialog.Builder(activity)
                    .setTitle("Delete Credential")
                    .setMessage("Delete credential for " + rpIdStr + "?")
                    .setPositiveButton("Delete", (dialog, which) -> deletePasskey(rpId, rpIdStr))
                    .setNegativeButton("Cancel", null)
                    .show();
        }
        
        private void deletePasskey(byte[] rpId, String rpIdStr) {
            if (activity.passkey != null) {
                try {
                    boolean removed = activity.passkey.removeResidentCredential(rpId);
                    if (removed) {
                        File appDataDir = activity.getFilesDir();
                        File passkeyFile = new File(appDataDir, activity.fileName);
                        Passkey.writeKey(activity.passkey, activity.passwordHash, passkeyFile);
                        
                        Toast.makeText(activity, "Credential deleted: " + rpIdStr, Toast.LENGTH_SHORT).show();
                        activity.recreate();
                    } else {
                        Toast.makeText(activity, "Failed to delete credential", Toast.LENGTH_SHORT).show();
                    }
                } catch (Exception e) {
                    Log.e(TAG, "Error deleting credential", e);
                    Toast.makeText(activity, "Error: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                }
            }
        }
        
        static class ViewHolder extends RecyclerView.ViewHolder {
            TextView text1;
            TextView text2;
            
            ViewHolder(View view) {
                super(view);
                text1 = view.findViewById(android.R.id.text1);
                text2 = view.findViewById(android.R.id.text2);
            }
        }
    }
    
    /**
     * Adapter for digital credentials
     */
    private static class DigitalCredentialAdapter extends RecyclerView.Adapter<DigitalCredentialAdapter.ViewHolder> {
        
        private final List<VerifiableCredential> credentials;
        private final ResidentCredentialsActivity activity;
        private final DateTimeFormatter dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd")
                .withZone(ZoneId.systemDefault());
        
        DigitalCredentialAdapter(List<VerifiableCredential> credentials, ResidentCredentialsActivity activity) {
            this.credentials = credentials;
            this.activity = activity;
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
            holder.credentialIcon.setImageResource(getIconForCredentialType(credType));
            holder.credentialType.setText(credType != null ? credType : "Digital Credential");
            
            String issuer = vc.getMetadata().getIssuerDid();
            if (issuer == null) {
                issuer = vc.getMetadata().getIssuerUrl();
            }
            holder.issuerName.setText(issuer != null ? issuer : "Unknown Issuer");
            
            Instant expiresAt = vc.getMetadata().getExpiresAt();
            if (expiresAt != null) {
                holder.expirationDate.setText(activity.getString(R.string.expires_format, 
                        dateFormatter.format(expiresAt)));
            } else {
                holder.expirationDate.setText(R.string.never_expires);
            }
            
            holder.statusIndicator.setText(R.string.credential_valid);
            holder.statusIndicator.setTextColor(0xFF4CAF50);
            
            holder.associatedPasskey.setText(activity.getString(R.string.passkey_association, 
                    activity.fileName != null ? activity.fileName : "Unknown"));
            
            holder.itemView.setOnClickListener(v -> showCredentialDetails(vc));
            holder.itemView.setOnLongClickListener(v -> {
                showDeleteDialog(vc);
                return true;
            });
        }
        
        @Override
        public int getItemCount() {
            return credentials.size();
        }
        
        /**
         * Maps credential type to appropriate icon resource.
         * @param credentialType The type of credential (e.g., "DriverLicense", "UniversityDegree")
         * @return Resource ID for the appropriate icon drawable
         */
        private int getIconForCredentialType(String credentialType) {
            if (credentialType == null) {
                return R.drawable.data_privacy_key;
            }
            
            String type = credentialType.toLowerCase();
            
            // Map common credential types to icons
            if (type.contains("driver") || type.contains("license") || type.contains("dl")) {
                return R.drawable.data_privacy_key; // TODO: Replace with driver's license icon
            } else if (type.contains("degree") || type.contains("diploma") || type.contains("education")) {
                return R.drawable.data_privacy_key; // TODO: Replace with education icon
            } else if (type.contains("passport")) {
                return R.drawable.data_privacy_key; // TODO: Replace with passport icon
            } else if (type.contains("health") || type.contains("medical")) {
                return R.drawable.data_privacy_key; // TODO: Replace with health icon
            } else if (type.contains("employee") || type.contains("work")) {
                return R.drawable.data_privacy_key; // TODO: Replace with employee badge icon
            } else {
                // Default icon for unknown credential types
                return R.drawable.data_privacy_key;
            }
        }

        private void showCredentialDetails(VerifiableCredential vc) {
            StringBuilder details = new StringBuilder();
            details.append("ID: ").append(vc.getId()).append("\n\n");
            details.append("Type: ").append(vc.getMetadata().getCredentialType()).append("\n\n");
            details.append("Issuer: ").append(vc.getMetadata().getIssuerDid()).append("\n\n");
            details.append("Format: ").append(vc.getFormat().getIdentifier());
            
            new AlertDialog.Builder(activity)
                    .setTitle("Credential Details")
                    .setMessage(details.toString())
                    .setPositiveButton("OK", null)
                    .show();
        }
        
        private void showDeleteDialog(VerifiableCredential vc) {
            new AlertDialog.Builder(activity)
                    .setTitle(R.string.delete_credential)
                    .setMessage("Delete " + vc.getMetadata().getCredentialType() + "?")
                    .setPositiveButton("Delete", (dialog, which) -> deleteCredential(vc))
                    .setNegativeButton("Cancel", null)
                    .show();
        }
        
        private void deleteCredential(VerifiableCredential vc) {
            if (activity.passkey != null) {
                try {
                    boolean removed = activity.passkey.removeVerifiableCredential(vc.getId());
                    if (removed) {
                        File appDataDir = activity.getFilesDir();
                        File passkeyFile = new File(appDataDir, activity.fileName);
                        Passkey.writeKey(activity.passkey, activity.passwordHash, passkeyFile);
                        
                        Toast.makeText(activity, R.string.credential_deleted, Toast.LENGTH_SHORT).show();
                        activity.recreate();
                    } else {
                        Toast.makeText(activity, R.string.credential_delete_failed, Toast.LENGTH_SHORT).show();
                    }
                } catch (Exception e) {
                    Log.e(TAG, "Error deleting credential", e);
                    Toast.makeText(activity, "Error: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                }
            }
        }
        
        static class ViewHolder extends RecyclerView.ViewHolder {
            ImageView credentialIcon;
            TextView credentialType;
            TextView issuerName;
            TextView expirationDate;
            TextView statusIndicator;
            TextView associatedPasskey;
            
            ViewHolder(View view) {
                super(view);
                credentialIcon = view.findViewById(R.id.credentialIcon);
                credentialType = view.findViewById(R.id.credentialType);
                issuerName = view.findViewById(R.id.issuerName);
                expirationDate = view.findViewById(R.id.expirationDate);
                statusIndicator = view.findViewById(R.id.statusIndicator);
                associatedPasskey = view.findViewById(R.id.associatedPasskey);
            }
        }
    }
}

// Made with Bob

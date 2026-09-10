/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credentials;

import android.app.PendingIntent;
import android.content.Intent;
import android.graphics.drawable.Icon;
import android.os.CancellationSignal;
import android.os.OutcomeReceiver;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.credentials.provider.BeginCreateCredentialRequest;
import androidx.credentials.provider.BeginCreateCredentialResponse;
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest;
import androidx.credentials.provider.BeginGetCredentialRequest;
import androidx.credentials.provider.BeginGetCredentialResponse;
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption;
import androidx.credentials.provider.CreateEntry;
import androidx.credentials.provider.CredentialProviderService;
import androidx.credentials.provider.ProviderClearCredentialStateRequest;
import androidx.credentials.provider.PublicKeyCredentialEntry;
import androidx.credentials.exceptions.ClearCredentialException;
import androidx.credentials.exceptions.CreateCredentialException;
import androidx.credentials.exceptions.GetCredentialException;
import com.isfs.blekey.activity.CredentialManagerProviderActivity;
import com.isfs.blekey.util.FileUtils;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Passkey Credential Provider Service — integrates with Android Credential Manager.
 *
 * <p>Handles {@code onBeginGetCredentialRequest} and {@code onBeginCreateCredentialRequest}
 * by enumerating resident {@code .passkey} wallet files and returning one
 * {@link PublicKeyCredentialEntry} / {@link CreateEntry} per wallet. The actual
 * PIN-entry + crypto work is performed by {@link CredentialManagerProviderActivity}
 * once the user selects an entry.</p>
 *
 * <p>GET flow uses {@link PublicKeyCredentialEntry} (not {@code AuthenticationAction}) so
 * the activity's {@link androidx.credentials.provider.PendingIntentHandler#setGetCredentialResponse}
 * call is delivered directly to the calling app without a second framework round-trip.</p>
 */
public class DigitalCredentialProviderService extends CredentialProviderService {

    private static final String TAG = "DigitalCredProvSvc";

    /** Extra key: flow type passed to {@link CredentialManagerProviderActivity}. */
    public static final String EXTRA_FLOW_TYPE   = "flow_type";
    /** Extra value: get-assertion flow. */
    public static final String FLOW_GET          = "get";
    /** Extra value: make-credential flow. */
    public static final String FLOW_CREATE       = "create";
    /** Extra key: wallet file name (basename only) passed to the activity. */
    public static final String EXTRA_WALLET_FILE = "wallet_file_name";

    // -------------------------------------------------------------------------
    // onBeginGetCredentialRequest
    // -------------------------------------------------------------------------

    @Override
    public void onBeginGetCredentialRequest(
            @NonNull BeginGetCredentialRequest request,
            @NonNull CancellationSignal cancellationSignal,
            @NonNull OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException> callback) {

        // Collect the first BeginGetPublicKeyCredentialOption — required by
        // PublicKeyCredentialEntry constructor and carries the request JSON.
        BeginGetPublicKeyCredentialOption passkeyOption = null;
        for (androidx.credentials.provider.BeginGetCredentialOption option
                : request.getBeginGetCredentialOptions()) {
            if (option instanceof BeginGetPublicKeyCredentialOption) {
                passkeyOption = (BeginGetPublicKeyCredentialOption) option;
                break;
            }
        }
        if (passkeyOption == null) {
            callback.onResult(new BeginGetCredentialResponse());
            return;
        }

        List<File> wallets = FileUtils.listPasskeys();
        List<androidx.credentials.provider.CredentialEntry> entries = new ArrayList<>();
        if (wallets != null) {
            int requestCode = 1000;
            for (File wallet : wallets) {
                String displayName = wallet.getName().replace(".passkey", "");
                Intent intent = new Intent(this, CredentialManagerProviderActivity.class);
                intent.putExtra(EXTRA_FLOW_TYPE, FLOW_GET);
                intent.putExtra(EXTRA_WALLET_FILE, wallet.getName());
                PendingIntent pi = PendingIntent.getActivity(
                        this, requestCode++, intent,
                        PendingIntent.FLAG_MUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
                entries.add(new PublicKeyCredentialEntry(
                        this,
                        displayName,       // username (visible label)
                        pi,
                        passkeyOption,
                        null,              // displayName (secondary label) — null = omit
                        null,              // lastUsedTime
                        Icon.createWithResource(this, android.R.drawable.ic_menu_mylocation),
                        false,             // isAutoSelectAllowed
                        false              // isDefaultIconPreferredAsSingleProvider
                ));
            }
        }
        Log.d(TAG, "onBeginGetCredentialRequest: returning " + entries.size() + " entries");
        callback.onResult(new BeginGetCredentialResponse.Builder()
                .setCredentialEntries(entries)
                .build());
    }

    // -------------------------------------------------------------------------
    // onBeginCreateCredentialRequest
    // -------------------------------------------------------------------------

    @Override
    public void onBeginCreateCredentialRequest(
            @NonNull BeginCreateCredentialRequest request,
            @NonNull CancellationSignal cancellationSignal,
            @NonNull OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException> callback) {

        if (!(request instanceof BeginCreatePublicKeyCredentialRequest)) {
            callback.onResult(new BeginCreateCredentialResponse(new ArrayList<>(), null));
            return;
        }

        List<File> wallets = FileUtils.listPasskeys();
        List<CreateEntry> entries = new ArrayList<>();
        if (wallets != null) {
            int requestCode = 2000;
            for (File wallet : wallets) {
                String displayName = wallet.getName().replace(".passkey", "");
                Intent intent = new Intent(this, CredentialManagerProviderActivity.class);
                intent.putExtra(EXTRA_FLOW_TYPE, FLOW_CREATE);
                intent.putExtra(EXTRA_WALLET_FILE, wallet.getName());
                PendingIntent pi = PendingIntent.getActivity(
                        this, requestCode++, intent,
                        PendingIntent.FLAG_MUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
                entries.add(new CreateEntry.Builder(displayName, pi).build());
            }
        }
        Log.d(TAG, "onBeginCreateCredentialRequest: returning " + entries.size() + " entries");
        callback.onResult(new BeginCreateCredentialResponse(entries, null));
    }

    // -------------------------------------------------------------------------
    // onClearCredentialStateRequest
    // -------------------------------------------------------------------------

    @Override
    public void onClearCredentialStateRequest(
            @NonNull ProviderClearCredentialStateRequest request,
            @NonNull CancellationSignal cancellationSignal,
            @NonNull OutcomeReceiver<Void, ClearCredentialException> callback) {
        // No sticky state to clear.
        callback.onResult(null);
    }
}

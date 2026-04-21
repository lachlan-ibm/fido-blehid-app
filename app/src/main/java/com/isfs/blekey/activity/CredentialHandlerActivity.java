package com.isfs.blekey.activity;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;


/**
 * Activity for handling deep links from QR codes.
 * Routes credential offers and presentation requests to appropriate activities.
 * 
 * Supported URI schemes:
 * - openid-credential-offer:// - Credential issuance flow
 * - openid4vp:// - Credential presentation flow
 * - openid:// - Generic OpenID flow (parsed to determine type)
 */
public class CredentialHandlerActivity extends AppCompatActivity {
    
    private static final String TAG = CredentialHandlerActivity.class.getCanonicalName();
    
    private static final String SCHEME_CREDENTIAL_OFFER = "openid-credential-offer";
    private static final String SCHEME_PRESENTATION = "openid4vp";
    private static final String SCHEME_OPENID = "openid";
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        Intent intent = getIntent();
        Uri data = intent.getData();
        
        if (data == null) {
            Log.e(TAG, "No URI data in intent");
            showErrorAndFinish("Invalid credential request");
            return;
        }
        
        Log.i(TAG, "Received deep link: " + data.toString());
        
        String scheme = data.getScheme();
        if (scheme == null) {
            Log.e(TAG, "No scheme in URI: " + data);
            showErrorAndFinish("Invalid credential request");
            return;
        }
        
        try {
            switch (scheme.toLowerCase()) {
                case SCHEME_CREDENTIAL_OFFER:
                    handleCredentialOffer(data);
                    break;
                    
                case SCHEME_PRESENTATION:
                    handlePresentationRequest(data);
                    break;
                    
                case SCHEME_OPENID:
                    handleGenericOpenId(data);
                    break;
                    
                default:
                    Log.e(TAG, "Unsupported URI scheme: " + scheme);
                    showErrorAndFinish("Unsupported credential request type");
                    break;
            }
        } catch (Exception e) {
            Log.e(TAG, "Error handling deep link", e);
            showErrorAndFinish("Failed to process credential request: " + e.getMessage());
        }
    }
    
    /**
     * Handle credential offer URI.
     * Format: openid-credential-offer://?credential_offer=<encoded_offer>
     * or: openid-credential-offer://?credential_offer_uri=<url>
     */
    private void handleCredentialOffer(Uri uri) {
        Log.i(TAG, "Handling credential offer");
        
        String credentialOffer = uri.getQueryParameter("credential_offer");
        String credentialOfferUri = uri.getQueryParameter("credential_offer_uri");
        
        if (credentialOffer == null && credentialOfferUri == null) {
            Log.e(TAG, "No credential_offer or credential_offer_uri parameter");
            showErrorAndFinish("Invalid credential offer");
            return;
        }
        
        String fullUri = uri.toString();

        Intent issuanceIntent = new Intent(this, ManageActivity.class);
        issuanceIntent.setAction("com.isfs.blekey.CREDENTIAL_OFFER");
        issuanceIntent.putExtra("credential_offer_uri", fullUri);
        issuanceIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);

        Log.i(TAG, "Routing to [ManageActivity] for credential issuance");
        startActivity(issuanceIntent);
        finish();
    }
    
    /**
     * Handle presentation request URI.
     * Format: openid4vp://?request_uri=<url>
     * or: openid4vp://?request=<encoded_request>
     */
    private void handlePresentationRequest(Uri uri) {
        Log.i(TAG, "Handling presentation request");
        
        String requestUri = uri.getQueryParameter("request_uri");
        String request = uri.getQueryParameter("request");
        
        if (requestUri == null && request == null) {
            Log.e(TAG, "No request_uri or request parameter");
            showErrorAndFinish("Invalid presentation request");
            return;
        }
        
        String requestData = requestUri != null ? requestUri : request;

        Intent presentationIntent = new Intent(this, ManageActivity.class);
        presentationIntent.setAction("com.isfs.blekey.PRESENTATION_REQUEST");
        presentationIntent.putExtra("presentation_request_uri", requestData);
        presentationIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);

        Log.i(TAG, "Routing to [ManageActivity] for credential presentation");
        startActivity(presentationIntent);
        finish();
    }
    
    /**
     * Handle generic OpenID URI.
     * Parses the URI to determine if it's a credential offer or presentation request.
     * Format: openid://?<parameters>
     */
    private void handleGenericOpenId(Uri uri) {
        Log.i(TAG, "Handling generic OpenID URI");
        
        if (uri.getQueryParameter("credential_offer") != null || 
            uri.getQueryParameter("credential_offer_uri") != null) {
            handleCredentialOffer(uri);
        } else if (uri.getQueryParameter("request_uri") != null || 
                   uri.getQueryParameter("request") != null) {
            handlePresentationRequest(uri);
        } else {
            Log.e(TAG, "Cannot determine OpenID flow type from URI: " + uri);
            showErrorAndFinish("Unsupported OpenID request");
        }
    }
    
    /**
     * Show error message and finish activity.
     */
    private void showErrorAndFinish(String message) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
        finish();
    }
}

// Made with Bob

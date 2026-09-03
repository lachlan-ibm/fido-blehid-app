/*
 * Copyright IBM 2025
 */

package com.isfs.blekey.bthid;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

/**
 * Manages persistent storage of device connection and HID enumeration state.
 * This allows state to survive app restarts and service lifecycle changes.
 */
public class DeviceStateManager {
    
    private static final String TAG = DeviceStateManager.class.getCanonicalName();
    private static final String PREFS_NAME = "device_states";
    private static final String KEY_PREFIX = "device_state_";
    
    private final SharedPreferences prefs;
    private final Context context;
    
    /**
     * Bluetooth connection state.
     */
    public enum BtState {
        DISCONNECTED,
        CONNECTED,
        ERROR
    }
    
    /**
     * HID service enumeration state.
     */
    public enum HidState {
        NOT_ENUMERATED,  // HID service not discovered yet
        ENUMERATED,      // HID Report Map read (service discovered)
        ACTIVE           // Notifications enabled (ready for input)
    }
    
    /**
     * Complete device state including both BT and HID status.
     */
    public static class DeviceState {
        public final String address;
        public String name;
        public BtState btState;
        public HidState hidState;
        public long lastUpdate;
        
        public DeviceState(@NonNull String address, @NonNull String name, 
                          @NonNull BtState btState, @NonNull HidState hidState) {
            this.address = address;
            this.name = name;
            this.btState = btState;
            this.hidState = hidState;
            this.lastUpdate = System.currentTimeMillis();
        }
        
        /**
         * Serialize to JSON for storage.
         */
        public JSONObject toJson() throws JSONException {
            JSONObject json = new JSONObject();
            json.put("address", address);
            json.put("name", name);
            json.put("btState", btState.name());
            json.put("hidState", hidState.name());
            json.put("lastUpdate", lastUpdate);
            return json;
        }
        
        /**
         * Deserialize from JSON.
         */
        public static DeviceState fromJson(JSONObject json) throws JSONException {
            String address = json.getString("address");
            String name = json.getString("name");
            BtState btState = BtState.valueOf(json.getString("btState"));
            HidState hidState = HidState.valueOf(json.getString("hidState"));
            
            DeviceState state = new DeviceState(address, name, btState, hidState);
            state.lastUpdate = json.getLong("lastUpdate");
            return state;
        }
        
        @Override
        public String toString() {
            return String.format("DeviceState{addr=%s, name=%s, bt=%s, hid=%s, updated=%d}",
                    address, name, btState, hidState, lastUpdate);
        }
    }
    
    /**
     * Creates a new DeviceStateManager.
     * 
     * @param context Application context
     */
    public DeviceStateManager(@NonNull Context context) {
        this.context = context.getApplicationContext();
        this.prefs = this.context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }
    
    /**
     * Saves device state to persistent storage.
     * 
     * @param address Device Bluetooth address
     * @param state Device state to save
     */
    public void saveDeviceState(@NonNull String address, @NonNull DeviceState state) {
        try {
            String key = KEY_PREFIX + address;
            String json = state.toJson().toString();
            prefs.edit().putString(key, json).apply();
            Log.d(TAG, "Saved state for " + address + ": " + state);
        } catch (JSONException e) {
            Log.e(TAG, "Failed to save device state for " + address, e);
        }
    }
    
    /**
     * Loads device state from persistent storage.
     * 
     * @param address Device Bluetooth address
     * @return Device state, or null if not found
     */
    @Nullable
    public DeviceState loadDeviceState(@NonNull String address) {
        try {
            String key = KEY_PREFIX + address;
            String json = prefs.getString(key, null);
            if (json == null) {
                return null;
            }
            DeviceState state = DeviceState.fromJson(new JSONObject(json));
            Log.d(TAG, "Loaded state for " + address + ": " + state);
            return state;
        } catch (JSONException e) {
            Log.e(TAG, "Failed to load device state for " + address, e);
            return null;
        }
    }
    
    /**
     * Loads all stored device states.
     * 
     * @return Map of device address to device state
     */
    @NonNull
    public Map<String, DeviceState> loadAllDeviceStates() {
        Map<String, DeviceState> states = new HashMap<>();
        Map<String, ?> allPrefs = prefs.getAll();
        
        for (Map.Entry<String, ?> entry : allPrefs.entrySet()) {
            String key = entry.getKey();
            if (key.startsWith(KEY_PREFIX)) {
                String address = key.substring(KEY_PREFIX.length());
                DeviceState state = loadDeviceState(address);
                if (state != null) {
                    states.put(address, state);
                }
            }
        }
        
        Log.d(TAG, "Loaded " + states.size() + " device states");
        return states;
    }
    
    /**
     * Clears stored state for a specific device.
     * 
     * @param address Device Bluetooth address
     */
    public void clearDeviceState(@NonNull String address) {
        String key = KEY_PREFIX + address;
        prefs.edit().remove(key).apply();
        Log.d(TAG, "Cleared state for " + address);
    }
    
    /**
     * Clears all stored device states.
     */
    public void clearAllDeviceStates() {
        SharedPreferences.Editor editor = prefs.edit();
        Map<String, ?> allPrefs = prefs.getAll();
        
        for (String key : allPrefs.keySet()) {
            if (key.startsWith(KEY_PREFIX)) {
                editor.remove(key);
            }
        }
        
        editor.apply();
        Log.d(TAG, "Cleared all device states");
    }
    
    /**
     * Updates only the BT state for a device, preserving other fields.
     * 
     * @param address Device Bluetooth address
     * @param btState New BT state
     */
    public void updateBtState(@NonNull String address, @NonNull BtState btState) {
        DeviceState state = loadDeviceState(address);
        if (state != null) {
            state.btState = btState;
            state.lastUpdate = System.currentTimeMillis();
            saveDeviceState(address, state);
        }
    }
    
    /**
     * Updates only the HID state for a device, preserving other fields.
     * 
     * @param address Device Bluetooth address
     * @param hidState New HID state
     */
    public void updateHidState(@NonNull String address, @NonNull HidState hidState) {
        DeviceState state = loadDeviceState(address);
        if (state != null) {
            state.hidState = hidState;
            state.lastUpdate = System.currentTimeMillis();
            saveDeviceState(address, state);
        }
    }
}

// Made with Bob

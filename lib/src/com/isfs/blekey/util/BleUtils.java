/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.util;

import java.util.UUID;

public class BleUtils {

    /** GATT Service UUIDs */
    public static final UUID SERVICE_GENERIC_ATTRIBUTE  = getCharateristicUuid(0x1801);
    public static final UUID SERVICE_BLE_HID            = getCharateristicUuid(0x1812);
    public static final UUID SERVICE_DEVICE_INFORMATION = getCharateristicUuid(0x180A);
    public static final UUID SERVICE_BATTERY            = getCharateristicUuid(0x180F);

    /** Generic Attribute service characteristics */
    public static final UUID CHARACTERISTIC_SERVICE_CHANGED = getCharateristicUuid(0x2A05);

    public static UUID getCharateristicUuid(int serviceId) {
        return UUID.fromString(
            String.format("0000%04X-0000-1000-8000-00805F9B34FB", serviceId & 0xffff) );
    }

    public static boolean isShortUuid(UUID uuid) {
        return (uuid.getMostSignificantBits() & 0xffff0000ffffffffL) == 0L && uuid.getLeastSignificantBits() == 0L;
    }

    public static boolean matches(UUID src, UUID dst) {
        if(isShortUuid(src) || isShortUuid(dst)) {
            long srcShort = src.getMostSignificantBits() & 0x0000ffff00000000L;
            long dstShort = dst.getMostSignificantBits() & 0x0000ffff00000000L;
            return srcShort == dstShort;
        } else {
            return src.equals(dst);
        }
    }
}
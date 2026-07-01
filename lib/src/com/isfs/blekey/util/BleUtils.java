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
    public static final UUID SERVICE_FIDO               = getCharateristicUuid(0xFFFD);

    /** Generic Attribute service characteristics */
    public static final UUID CHARACTERISTIC_SERVICE_CHANGED = getCharateristicUuid(0x2A05);

    /** FIDO Service Characteristics (CTAP spec §11.4.5) */
    public static final UUID CHAR_FIDO_CONTROL_POINT =
        UUID.fromString("F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB");
    public static final UUID CHAR_FIDO_STATUS =
        UUID.fromString("F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623BB");
    public static final UUID CHAR_FIDO_CONTROL_POINT_LENGTH =
        UUID.fromString("F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623BB");
    public static final UUID CHAR_FIDO_SERVICE_REVISION_BITFIELD =
        UUID.fromString("F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB");

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
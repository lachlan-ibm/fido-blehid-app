/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.util;

import java.util.UUID;

public class BleUtils {
    
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
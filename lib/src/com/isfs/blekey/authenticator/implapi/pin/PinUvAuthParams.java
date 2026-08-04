/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.authenticator.implapi.pin;

import com.isfs.blekey.ctap.Ctap2StatusCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Data Transfer Object for PIN/UV authentication parameters.
 * Encapsulates all parameters needed for PIN/UV authentication verification.
 * Provides type-safe parsing and validation of request parameters.
 */
class PinUvAuthParams {

    private static final Logger logger = LoggerFactory.getLogger(PinUvAuthParams.class);

    final byte[] pinUvAuthParam;
    final Integer pinUvAuthProtocol;
    final boolean uvRequested;
    final String rpId;
    final Ctap2StatusCode errorCode;

    private PinUvAuthParams(byte[] pinUvAuthParam, Integer pinUvAuthProtocol,
                            boolean uvRequested, String rpId, Ctap2StatusCode errorCode) {
        this.pinUvAuthParam = pinUvAuthParam;
        this.pinUvAuthProtocol = pinUvAuthProtocol;
        this.uvRequested = uvRequested;
        this.rpId = rpId;
        this.errorCode = errorCode;
    }

    /**
     * Checks if parsing was successful.
     * @return true if no errors occurred during parsing
     */
    boolean isValid() {
        return errorCode == null;
    }

    /**
     * Parses and validates PIN/UV authentication parameters from the request.
     *
     * @param req The request parameters map
     * @return PinUvAuthParams containing validated parameters or error code
     */
    static PinUvAuthParams parse(Map<Integer, Object> req) {
        // Extract pinUvAuthParam (0x08) - optional
        Object paramObj = req.get(0x08);
        byte[] pinUvAuthParam = null;
        if (paramObj != null) {
            if (!(paramObj instanceof byte[])) {
                logger.error("pinUvAuthParam (0x08) is not a byte array");
                return new PinUvAuthParams(null, null, false, null, Ctap2StatusCode.INVALID_PARAMETER);
            }
            pinUvAuthParam = (byte[]) paramObj;
        }

        // Extract pinUvAuthProtocol (0x09) - optional
        Object protocolObj = req.get(0x09);
        Integer pinUvAuthProtocol = null;
        if (protocolObj != null) {
            if (!(protocolObj instanceof Integer)) {
                logger.error("pinUvAuthProtocol (0x09) is not an integer");
                return new PinUvAuthParams(null, null, false, null, Ctap2StatusCode.INVALID_PARAMETER);
            }
            pinUvAuthProtocol = (Integer) protocolObj;
        }

        // Extract options (0x07) - optional
        Object optionsObj = req.get(0x07);
        boolean uvRequested = false;
        if (optionsObj != null) {
            if (!(optionsObj instanceof Map)) {
                logger.error("options (0x07) is not a map");
                return new PinUvAuthParams(null, null, false, null, Ctap2StatusCode.INVALID_PARAMETER);
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> options = (Map<String, Object>) optionsObj;
            Object uvObj = options.get("uv");
            if (uvObj instanceof Boolean) {
                uvRequested = (Boolean) uvObj;
            }
        }

        // Extract and validate RP (0x02) - required
        Object rpObj = req.get(0x02);
        if (rpObj == null) {
            logger.error("Missing RP parameter (0x02)");
            return new PinUvAuthParams(null, null, false, null, Ctap2StatusCode.MISSING_PARAMETER);
        }
        if (!(rpObj instanceof Map)) {
            logger.error("RP parameter (0x02) is not a map");
            return new PinUvAuthParams(null, null, false, null, Ctap2StatusCode.INVALID_PARAMETER);
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> rp = (Map<String, Object>) rpObj;
        Object rpIdObj = rp.get("id");
        if (rpIdObj == null) {
            logger.error("Missing RP ID in RP parameter");
            return new PinUvAuthParams(null, null, false, null, Ctap2StatusCode.MISSING_PARAMETER);
        }
        if (!(rpIdObj instanceof String)) {
            logger.error("RP ID is not a string");
            return new PinUvAuthParams(null, null, false, null, Ctap2StatusCode.INVALID_PARAMETER);
        }

        String rpId = (String) rpIdObj;

        return new PinUvAuthParams(pinUvAuthParam, pinUvAuthProtocol, uvRequested, rpId, null);
    }
}

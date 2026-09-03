/*
 * Copyright IBM 2025
 */
package com.isfs.blekey.transport;

/**
 * Service-to-transport contract.  Neither {@code bthid} nor {@code fidoble} owns this
 * interface; both depend on it.
 *
 * <p>Each transport implementation is responsible for framing: {@link #sendResponse}
 * receives a fully-framed byte array appropriate to the transport's protocol layer.
 * The service never touches framing.</p>
 */
public interface ICtapTransport {

    /**
     * Send a fully-framed CTAP response to the connected host.
     * Framing is transport-specific and must be applied by the caller before
     * invoking this method.
     *
     * @param framedResponse Framed bytes ready for the wire.
     */
    void sendResponse(byte[] framedResponse);

    /**
     * Returns {@code true} when at least one host is connected and the transport
     * is ready to accept outbound frames.
     */
    boolean isReady();

    /**
     * Returns the framing protocol in use.
     */
    CtapTransportType getType();
}

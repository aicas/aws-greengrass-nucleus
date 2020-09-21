/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 */

package com.aws.greengrass.iot;

import com.aws.greengrass.deployment.DeviceConfiguration;
import com.aws.greengrass.deployment.exceptions.AWSIotException;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.util.Coerce;
import software.amazon.awssdk.crt.http.HttpClientConnection;
import software.amazon.awssdk.crt.http.HttpClientConnectionManager;
import software.amazon.awssdk.crt.http.HttpClientConnectionManagerOptions;
import software.amazon.awssdk.crt.http.HttpException;
import software.amazon.awssdk.crt.io.ClientBootstrap;
import software.amazon.awssdk.crt.io.EventLoopGroup;
import software.amazon.awssdk.crt.io.HostResolver;
import software.amazon.awssdk.crt.io.SocketOptions;
import software.amazon.awssdk.crt.io.TlsContext;
import software.amazon.awssdk.crt.io.TlsContextOptions;

import java.io.Closeable;
import java.net.URI;
import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.inject.Inject;

public class IotConnectionManager implements Closeable {
    // TODO: Move Iot related classes to a central location
    private static final Logger LOGGER = LogManager.getLogger(IotConnectionManager.class);
    // TODO: ALPN support, and validate how does it work if port is also part of URL
    private static final int IOT_PORT = 8443;
    // Max wait time for device to establish mTLS connection with IOT core
    private static final long TIMEOUT_FOR_CONNECTION_SETUP_SECONDS = Duration.ofMinutes(1).getSeconds();
    private final HttpClientConnectionManager connManager;

    private final EventLoopGroup eventLoopGroup;
    private final HostResolver resolver;
    private final ClientBootstrap clientBootstrap;

    /**
     * Constructor.
     *
     * @param deviceConfiguration Device configuration helper getting cert and keys for mTLS
     */
    @Inject
    public IotConnectionManager(final DeviceConfiguration deviceConfiguration) {
        eventLoopGroup = new EventLoopGroup(1);
        resolver = new HostResolver(eventLoopGroup);
        clientBootstrap = new ClientBootstrap(eventLoopGroup, resolver);
        this.connManager = initConnectionManager(deviceConfiguration);
    }

    private HttpClientConnectionManager initConnectionManager(DeviceConfiguration deviceConfiguration) {
        final String certPath = Coerce.toString(deviceConfiguration.getCertificateFilePath());
        final String keyPath = Coerce.toString(deviceConfiguration.getPrivateKeyFilePath());
        final String caPath = Coerce.toString(deviceConfiguration.getRootCAFilePath());
        try (TlsContextOptions tlsCtxOptions = TlsContextOptions.createWithMtlsFromPath(certPath, keyPath)) {
            // TODO: Proxy support, ALPN support. Reuse connections across kernel
            tlsCtxOptions.overrideDefaultTrustStoreFromPath(null, caPath);
            return HttpClientConnectionManager
                    .create(new HttpClientConnectionManagerOptions().withClientBootstrap(clientBootstrap)
                            .withSocketOptions(new SocketOptions()).withTlsContext(new TlsContext(tlsCtxOptions))
                            .withPort(IOT_PORT).withUri(URI.create(
                                    "https://" + Coerce.toString(deviceConfiguration.getIotCredentialEndpoint()))));
        }
    }

    /**
     * Get a connection object for sending requests.
     *
     * @return {@link HttpClientConnection}
     * @throws AWSIotException when getting a connection from underlying manager fails.
     */
    public HttpClientConnection getConnection() throws AWSIotException {
        try {
            return connManager.acquireConnection().get(TIMEOUT_FOR_CONNECTION_SETUP_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException | ExecutionException | TimeoutException | HttpException e) {
            LOGGER.error("Getting connection failed for endpoint {} with error {} ", connManager.getUri(), e);
            throw new AWSIotException(e);
        }
    }

    /**
     * Get the host string underlying connection manager.
     *
     * @return Host string to be used in HTTP Host headers
     */
    public String getHost() {
        return connManager.getUri().getHost();
    }

    /**
     * Clean up underlying connections and close gracefully.
     */
    @Override
    public void close() {
        connManager.close();
        clientBootstrap.close();
        resolver.close();
        eventLoopGroup.close();
    }

}
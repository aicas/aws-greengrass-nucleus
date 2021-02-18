/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.plugins;

import com.aws.greengrass.componentmanager.builtins.ArtifactDownloader;
import com.aws.greengrass.componentmanager.exceptions.PackageDownloadException;
import com.aws.greengrass.componentmanager.models.ComponentArtifact;
import com.aws.greengrass.componentmanager.models.ComponentIdentifier;
import com.aws.greengrass.componentmanager.plugins.exceptions.ImagePullRetryableException;
import com.aws.greengrass.componentmanager.plugins.exceptions.ImagePullServiceException;
import com.aws.greengrass.util.RetryUtils;
import lombok.AccessLevel;
import lombok.Setter;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.ecr.model.ServerException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import javax.inject.Inject;


public class DockerImageDownloader extends ArtifactDownloader {

    // ImagePullServiceException corresponds to `Service unavailable` error from the docker engine. We retry on
    // this error for a finite count in case it's due to network issue or a problem with docker's cloud service. But
    // give up after that because it can also indicate problems with the docker engine instance or proxy configuration
    // in which case auto recovery is not possible.
    // TODO: Consider adding specific mechanism to check if connectivity is available and use that for retries instead
    //  of errors which are not always indicative of a recoverable issue
    @Setter(AccessLevel.PACKAGE)
    private RetryUtils.RetryConfig retryConfig =
            RetryUtils.RetryConfig.builder().initialRetryInterval(Duration.ofMinutes(1L))
                    .maxRetryInterval(Duration.ofMinutes(1L)).maxAttempt(10).retryableExceptions(
                    Arrays.asList(ImagePullRetryableException.class, ImagePullServiceException.class,
                            SdkClientException.class, ServerException.class)).build();
    @Inject
    private EcrAccessor ecrAccessor;
    @Inject
    private DefaultDockerClient dockerClient;

    public DockerImageDownloader(ComponentIdentifier identifier, ComponentArtifact artifact, Path artifactDir) {
        super(identifier, artifact, artifactDir);
    }

    DockerImageDownloader(ComponentIdentifier identifier, ComponentArtifact artifact, Path artifactDir,
                          DefaultDockerClient dockerClient, EcrAccessor ecrAccessor) {
        this(identifier, artifact, artifactDir);
        this.dockerClient = dockerClient;
        this.ecrAccessor = ecrAccessor;
    }

    @Override
    @SuppressWarnings({"PMD.AvoidCatchingGenericException", "PMD.AvoidRethrowingException"})
    public File download() throws PackageDownloadException, IOException, InterruptedException {
        // Check that Docker engine is installed
        if (!dockerClient.dockerInstalled()) {
            throw new PackageDownloadException("Docker engine is not installed on the device, please ensure it's "
                    + "installed and redo the deployment");
        }

        Image image = Image.fromArtifactUri(artifact.getArtifactUri());
        if (image.getRegistry().isEcrRegistry() && image.getRegistry().isPrivateRegistry()) {
            // Get auth token for ECR
            try {
                RetryUtils.runWithRetry(retryConfig, () -> {
                    Registry.Credentials credentials = ecrAccessor.getCredentials(image.getRegistry().getRegistryId());

                    image.getRegistry().setCredentials(credentials);
                    return null;
                }, "get-ecr-auth-token", logger);
            } catch (InterruptedException e) {
                throw e;
            } catch (Exception e) {
                throw new PackageDownloadException(getErrorString("Failed to get auth token for docker login"), e);
            }

            // Login to registry
            try {
                RetryUtils.runWithRetry(retryConfig, () -> dockerClient.login(image.getRegistry()), "docker-login",
                        logger);
            } catch (InterruptedException e) {
                throw e;
            } catch (Exception e) {
                throw new PackageDownloadException(getErrorString("Failed to login to docker registry"), e);
            }
        }

        // Docker pull
        // TODO : Redo credential fetching and login if ECR registry credentials expire by the time pull is attempted
        try {
            RetryUtils.runWithRetry(retryConfig, () -> dockerClient.pullImage(image), "docker-pull-image", logger);
        } catch (InterruptedException e) {
            throw e;
        } catch (Exception e) {
            throw new PackageDownloadException(getErrorString("Failed to download docker image"), e);
        }

        // No file resources available since image artifacts are stored in docker's image store
        return null;
    }

    @Override
    protected long download(long rangeStart, long rangeEnd, MessageDigest messageDigest)
            throws PackageDownloadException, InterruptedException {
        // N/A since handling partial download is managed by docker engine
        return 0;
    }

    @Override
    public boolean downloadRequired() {
        // TODO : Consider executing `docker image ls` to see if the required image version(tag/digest) already
        //  exists to save a download attempt
        return false;
    }

    @Override
    public Optional<String> checkDownloadable() {
        // TODO : Maybe worth checking if device is configured such that it can get TES credentials for ECR.
        // N/A for images from other registries
        return Optional.empty();
    }

    @Override
    public Long getDownloadSize() throws PackageDownloadException, InterruptedException {
        // Not supported for docker images
        return null;
    }

    @Override
    public String getArtifactFilename() {
        // Not applicable for docker images since docker engine abstracts this
        return null;
    }

    @Override
    public boolean checkComponentStoreSize() {
        // Not applicable for docker images since docker has its own image store
        return false;
    }

    @Override
    public boolean canSetFilePermissions() {
        // Not applicable for docker images since docker has its own image store
        return false;
    }

    @Override
    public boolean canUnarchiveArtifact() {
        // Not applicable for docker images since docker engine abstracts this
        return false;
    }
}

/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.plugins;

import com.aws.greengrass.componentmanager.exceptions.PackageDownloadException;
import com.aws.greengrass.componentmanager.models.ComponentArtifact;
import com.aws.greengrass.componentmanager.models.ComponentIdentifier;
import com.aws.greengrass.componentmanager.plugins.exceptions.ImagePullRetryableException;
import com.aws.greengrass.componentmanager.plugins.exceptions.ImagePullServiceException;
import com.aws.greengrass.componentmanager.plugins.exceptions.InvalidImageOrAccessDeniedException;
import com.aws.greengrass.componentmanager.plugins.exceptions.RegistryAuthException;
import com.aws.greengrass.componentmanager.plugins.exceptions.UserNotAuthorizedForDockerException;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import com.aws.greengrass.util.RetryUtils;
import com.vdurmont.semver4j.Semver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.ecr.model.ServerException;

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

import static com.aws.greengrass.testcommons.testutilities.ExceptionLogProtector.ignoreExceptionOfType;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith({MockitoExtension.class, GGExtension.class})
public class DockerImageDownloaderTest {
    private static ComponentIdentifier TEST_COMPONENT_ID =
            new ComponentIdentifier("test.container.component", new Semver("1.0.0"));
    private final RetryUtils.RetryConfig retryConfig =
            RetryUtils.RetryConfig.builder().initialRetryInterval(Duration.ofMillis(50L))
                    .maxRetryInterval(Duration.ofMillis(50L)).maxAttempt(2).retryableExceptions(
                    Arrays.asList(ImagePullRetryableException.class, ImagePullServiceException.class,
                            SdkClientException.class, ServerException.class)).build();
    @Mock
    private DefaultDockerClient dockerClient;
    @Mock
    private EcrAccessor ecrAccessor;
    @Mock
    private Path artifactDir;

    @Test
    void GIVEN_a_container_component_with_an_ecr_image_with_digest_WHEN_deployed_THEN_download_image_artifact()
            throws Exception {
        URI artifactUri =
                new URI("docker:012345678910.dkr.ecr.us-east-1.amazonaws.com/testimage@sha256:5442792a-752c-11eb-9439-0242ac130002");
        Image image = Image.fromArtifactUri(artifactUri);

        when(ecrAccessor.getCredentials("012345678910"))
                .thenReturn(new Registry.Credentials("username", "password", Instant.now().plusSeconds(60)));
        when(dockerClient.dockerInstalled()).thenReturn(true);
        when(dockerClient.login(image.getRegistry())).thenReturn(true);
        when(dockerClient.pullImage(image)).thenReturn(true);

        DockerImageDownloader downloader = new DockerImageDownloader(TEST_COMPONENT_ID,
                ComponentArtifact.builder().artifactUri(artifactUri).build(), artifactDir, dockerClient, ecrAccessor);
        downloader.setRetryConfig(retryConfig);

        downloader.download();

        assertEquals("testimage", image.getName());
        assertEquals("sha256:5442792a-752c-11eb-9439-0242ac130002", image.getDigest());
        assertNull(image.getTag());
        assertTrue(image.getRegistry().isEcrRegistry());
        assertTrue(image.getRegistry().isPrivateRegistry());
        assertEquals("012345678910.dkr.ecr.us-east-1.amazonaws.com", image.getRegistry().getEndpoint());
        assertEquals("012345678910", image.getRegistry().getRegistryId());

        verify(ecrAccessor).getCredentials("012345678910");
        verify(dockerClient).pullImage(image);
    }

    @Test
    void GIVEN_a_container_component_with_an_ecr_image_with_tag_WHEN_deployed_THEN_download_image_artifact()
            throws Exception {
        URI artifactUri = new URI("docker:012345678910.dkr.ecr.us-east-1.amazonaws.com/testimage:sometag");
        Image image = Image.fromArtifactUri(artifactUri);
        when(ecrAccessor.getCredentials("012345678910"))
                .thenReturn(new Registry.Credentials("username", "password", Instant.now().plusSeconds(60)));
        when(dockerClient.dockerInstalled()).thenReturn(true);
        when(dockerClient.login(image.getRegistry())).thenReturn(true);
        when(dockerClient.pullImage(image)).thenReturn(true);

        DockerImageDownloader downloader = new DockerImageDownloader(TEST_COMPONENT_ID,
                ComponentArtifact.builder().artifactUri(artifactUri).build(), artifactDir, dockerClient, ecrAccessor);
        downloader.setRetryConfig(retryConfig);

        downloader.download();

        assertEquals("testimage", image.getName());
        assertEquals("sometag", image.getTag());
        assertNull(image.getDigest());
        assertTrue(image.getRegistry().isEcrRegistry());
        assertTrue(image.getRegistry().isPrivateRegistry());
        assertEquals("012345678910.dkr.ecr.us-east-1.amazonaws.com", image.getRegistry().getEndpoint());
        assertEquals("012345678910", image.getRegistry().getRegistryId());

        verify(ecrAccessor).getCredentials("012345678910");
        verify(dockerClient).pullImage(image);
    }

    @Test
    void GIVEN_a_container_component_with_a_public_ecr_image_WHEN_deployed_THEN_download_image_artifact()
            throws Exception {
        URI artifactUri = new URI("docker:public.ecr.aws/a1b2c3d4/testimage:sometag");
        Image image = Image.fromArtifactUri(artifactUri);
        when(dockerClient.dockerInstalled()).thenReturn(true);
        when(dockerClient.pullImage(image)).thenReturn(true);

        DockerImageDownloader downloader = new DockerImageDownloader(TEST_COMPONENT_ID,
                ComponentArtifact.builder().artifactUri(artifactUri).build(), artifactDir, dockerClient, ecrAccessor);
        downloader.setRetryConfig(retryConfig);

        downloader.download();

        assertEquals("testimage", image.getName());
        assertEquals("sometag", image.getTag());
        assertNull(image.getDigest());
        assertTrue(image.getRegistry().isEcrRegistry());
        assertFalse(image.getRegistry().isPrivateRegistry());
        assertEquals("public.ecr.aws/a1b2c3d4", image.getRegistry().getEndpoint());

        verify(ecrAccessor, never()).getCredentials(anyString());
        verify(dockerClient).pullImage(image);
        verify(dockerClient, never()).login(any());
    }

    @Test
    void GIVEN_a_container_component_with_a_public_dockerhub_image_WHEN_deployed_THEN_download_image_artifact()
            throws Exception {
        URI artifactUri = new URI("docker:registry.hub.docker.com/library/alpine:sometag");
        Image image = Image.fromArtifactUri(artifactUri);
        when(dockerClient.dockerInstalled()).thenReturn(true);
        when(dockerClient.pullImage(image)).thenReturn(true);

        DockerImageDownloader downloader = new DockerImageDownloader(TEST_COMPONENT_ID,
                ComponentArtifact.builder().artifactUri(artifactUri).build(), artifactDir, dockerClient, ecrAccessor);
        downloader.setRetryConfig(retryConfig);

        downloader.download();

        assertEquals("alpine", image.getName());
        assertEquals("sometag", image.getTag());
        assertNull(image.getDigest());
        assertFalse(image.getRegistry().isEcrRegistry());
        assertFalse(image.getRegistry().isPrivateRegistry());
        assertEquals("registry.hub.docker.com/library", image.getRegistry().getEndpoint());

        verify(ecrAccessor, never()).getCredentials(anyString());
        verify(dockerClient).pullImage(image);
    }

    @Test
    void GIVEN_a_container_component_in_deployment_WHEN_docker_not_installed_THEN_fail_deployment() throws Exception {
        URI artifactUri = new URI("docker:registry.hub.docker.com/library/alpine:sometag");
        Image image = Image.fromArtifactUri(artifactUri);
        when(dockerClient.dockerInstalled()).thenReturn(false);

        DockerImageDownloader downloader = new DockerImageDownloader(TEST_COMPONENT_ID,
                ComponentArtifact.builder().artifactUri(artifactUri).build(), artifactDir, dockerClient, ecrAccessor);
        downloader.setRetryConfig(retryConfig);

        Throwable err = assertThrows(PackageDownloadException.class, () -> downloader.download());
        assertThat(err.getMessage(), containsString("Docker engine is not installed on the device"));

        assertEquals("alpine", image.getName());
        assertEquals("sometag", image.getTag());
        assertNull(image.getDigest());
        assertFalse(image.getRegistry().isEcrRegistry());
        assertFalse(image.getRegistry().isPrivateRegistry());
        assertEquals("registry.hub.docker.com/library", image.getRegistry().getEndpoint());

        verify(ecrAccessor, never()).getCredentials(anyString());
        verify(dockerClient, never()).login(any());
        verify(dockerClient, never()).pullImage(any());
    }

    @Test
    void GIVEN_a_container_component_with_image_in_dockerhub_WHEN_image_not_public_THEN_fail_deployment()
            throws Exception {
        URI artifactUri = new URI("docker:registry.hub.docker.com/library/alpine:sometag");
        Image image = Image.fromArtifactUri(artifactUri);
        when(dockerClient.dockerInstalled()).thenReturn(true);
        when(dockerClient.pullImage(image)).thenThrow(new InvalidImageOrAccessDeniedException(
                "Invalid image or login - repository does not exist or may require 'docker login'"));

        DockerImageDownloader downloader = new DockerImageDownloader(TEST_COMPONENT_ID,
                ComponentArtifact.builder().artifactUri(artifactUri).build(), artifactDir, dockerClient, ecrAccessor);
        downloader.setRetryConfig(retryConfig);

        Throwable err = assertThrows(PackageDownloadException.class, () -> downloader.download());
        assertThat(err.getMessage(), containsString("Failed to download docker image"));
        assertTrue(err.getCause() instanceof InvalidImageOrAccessDeniedException);

        assertEquals("alpine", image.getName());
        assertEquals("sometag", image.getTag());
        assertNull(image.getDigest());
        assertFalse(image.getRegistry().isEcrRegistry());
        assertFalse(image.getRegistry().isPrivateRegistry());
        assertEquals("registry.hub.docker.com/library", image.getRegistry().getEndpoint());

        verify(ecrAccessor, never()).getCredentials(anyString());
        verify(dockerClient, never()).login(any());
        verify(dockerClient).pullImage(image);
    }

    @Test
    void GIVEN_a_container_component_with_image_in_ecr_WHEN_when_failed_to_get_credentials_THEN_fail_deployment()
            throws Exception {
        URI artifactUri = new URI("docker:012345678910.dkr.ecr.us-east-1.amazonaws.com/testimage:sometag");
        Image image = Image.fromArtifactUri(artifactUri);
        when(ecrAccessor.getCredentials("012345678910"))
                .thenThrow(new RegistryAuthException("Failed to get " + "credentials for ECR registry"));
        when(dockerClient.dockerInstalled()).thenReturn(true);

        DockerImageDownloader downloader = new DockerImageDownloader(TEST_COMPONENT_ID,
                ComponentArtifact.builder().artifactUri(artifactUri).build(), artifactDir, dockerClient, ecrAccessor);
        downloader.setRetryConfig(retryConfig);

        Throwable err = assertThrows(PackageDownloadException.class, () -> downloader.download());
        assertThat(err.getMessage(), containsString("Failed to get auth token for docker login"));
        assertTrue(err.getCause() instanceof RegistryAuthException);

        assertEquals("testimage", image.getName());
        assertEquals("sometag", image.getTag());
        assertNull(image.getDigest());
        assertTrue(image.getRegistry().isEcrRegistry());
        assertTrue(image.getRegistry().isPrivateRegistry());
        assertEquals("012345678910.dkr.ecr.us-east-1.amazonaws.com", image.getRegistry().getEndpoint());
        assertEquals("012345678910", image.getRegistry().getRegistryId());

        verify(ecrAccessor).getCredentials("012345678910");
        verify(dockerClient, never()).login(any());
        verify(dockerClient, never()).pullImage(any());
    }

    @Test
    void GIVEN_a_container_component_WHENn_failed_to_pull_image_THEN_fail_deployment(ExtensionContext context)
            throws Exception {
        ignoreExceptionOfType(context, ImagePullRetryableException.class);

        URI artifactUri = new URI("docker:registry.hub.docker.com/library/alpine:sometag");
        Image image = Image.fromArtifactUri(artifactUri);
        when(dockerClient.dockerInstalled()).thenReturn(true);
        // fail all retries
        when(dockerClient.pullImage(image)).thenThrow(new ImagePullRetryableException("Service Unavailable"));

        DockerImageDownloader downloader = new DockerImageDownloader(TEST_COMPONENT_ID,
                ComponentArtifact.builder().artifactUri(artifactUri).build(), artifactDir, dockerClient, ecrAccessor);
        downloader.setRetryConfig(retryConfig);

        Throwable err = assertThrows(PackageDownloadException.class, () -> downloader.download());
        assertThat(err.getMessage(), containsString("Failed to download docker image"));
        assertTrue(err.getCause() instanceof ImagePullRetryableException);

        assertEquals("alpine", image.getName());
        assertEquals("sometag", image.getTag());
        assertNull(image.getDigest());
        assertFalse(image.getRegistry().isEcrRegistry());
        assertFalse(image.getRegistry().isPrivateRegistry());
        assertEquals("registry.hub.docker.com/library", image.getRegistry().getEndpoint());

        verify(ecrAccessor, never()).getCredentials(anyString());
        verify(dockerClient, never()).login(any());
        // Invocations as many as the retry count should be expected
        verify(dockerClient, times(2)).pullImage(any());
    }

    @Test
    void GIVEN_a_container_component_WHENn_failed_to_pull_image_intermittently_THEN_retry_and_succeed(
            ExtensionContext context) throws Exception {
        ignoreExceptionOfType(context, ImagePullRetryableException.class);

        URI artifactUri = new URI("docker:registry.hub.docker.com/library/alpine:sometag");
        Image image = Image.fromArtifactUri(artifactUri);
        when(dockerClient.dockerInstalled()).thenReturn(true);
        // fail first attempt, succeed on next retry attempt
        when(dockerClient.pullImage(image)).thenThrow(new ImagePullRetryableException("Service Unavailable"))
                .thenReturn(true);

        DockerImageDownloader downloader = new DockerImageDownloader(TEST_COMPONENT_ID,
                ComponentArtifact.builder().artifactUri(artifactUri).build(), artifactDir, dockerClient, ecrAccessor);
        downloader.setRetryConfig(retryConfig);

        downloader.download();

        assertEquals("alpine", image.getName());
        assertEquals("sometag", image.getTag());
        assertNull(image.getDigest());
        assertFalse(image.getRegistry().isEcrRegistry());
        assertFalse(image.getRegistry().isPrivateRegistry());
        assertEquals("registry.hub.docker.com/library", image.getRegistry().getEndpoint());

        verify(ecrAccessor, never()).getCredentials(anyString());
        verify(dockerClient, never()).login(any());
        // Invocations as many as the retry count should be expected
        verify(dockerClient, times(2)).pullImage(any());
    }

    @Test
    void GIVEN_a_container_component_WHEN_greengrass_does_not_have_permissions_to_use_docker_daemon_THEN_fail_deployment()
            throws Exception {
        URI artifactUri = new URI("docker:012345678910.dkr.ecr.us-east-1.amazonaws.com/testimage:sometag");
        Image image = Image.fromArtifactUri(artifactUri);
        when(dockerClient.dockerInstalled()).thenReturn(true);
        when(dockerClient.login(any())).thenThrow(new UserNotAuthorizedForDockerException(
                "Got permission denied while trying to connect to the Docker daemon socket"));

        DockerImageDownloader downloader = new DockerImageDownloader(TEST_COMPONENT_ID,
                ComponentArtifact.builder().artifactUri(artifactUri).build(), artifactDir, dockerClient, ecrAccessor);
        downloader.setRetryConfig(retryConfig);

        Throwable err = assertThrows(PackageDownloadException.class, () -> downloader.download());
        assertThat(err.getMessage(), containsString("Failed to login to docker registry"));
        assertTrue(err.getCause() instanceof UserNotAuthorizedForDockerException);

        assertEquals("testimage", image.getName());
        assertEquals("sometag", image.getTag());
        assertNull(image.getDigest());
        assertTrue(image.getRegistry().isEcrRegistry());
        assertTrue(image.getRegistry().isPrivateRegistry());
        assertEquals("012345678910.dkr.ecr.us-east-1.amazonaws.com", image.getRegistry().getEndpoint());
        assertEquals("012345678910", image.getRegistry().getRegistryId());

        verify(ecrAccessor).getCredentials("012345678910");
        verify(dockerClient).login(any());
        verify(dockerClient, never()).pullImage(any());
    }

    @Test
    void GIVEN_a_container_component_with_no_registry_in_uri_WHEN_deployed_THEN_download_image_artifact_from_dockerhub()
            throws Exception {
        URI artifactUri = new URI("docker:alpine:sometag");
        Image image = Image.fromArtifactUri(artifactUri);
        when(dockerClient.dockerInstalled()).thenReturn(true);
        when(dockerClient.pullImage(image)).thenReturn(true);

        DockerImageDownloader downloader = new DockerImageDownloader(TEST_COMPONENT_ID,
                ComponentArtifact.builder().artifactUri(artifactUri).build(), artifactDir, dockerClient, ecrAccessor);
        downloader.setRetryConfig(retryConfig);

        downloader.download();

        assertEquals("alpine", image.getName());
        assertEquals("sometag", image.getTag());
        assertNull(image.getDigest());
        assertFalse(image.getRegistry().isEcrRegistry());
        assertFalse(image.getRegistry().isPrivateRegistry());
        assertEquals("registry.hub.docker.com/library", image.getRegistry().getEndpoint());

        verify(ecrAccessor, never()).getCredentials(anyString());
        verify(dockerClient, never()).login(any());
        verify(dockerClient).pullImage(image);
    }

    @Test
    void GIVEN_a_container_component_with_no_digest_or_tag_in_uri_WHEN_deployed_THEN_assume_latest_image_version()
            throws Exception {
        URI artifactUri = new URI("docker:alpine");
        Image image = Image.fromArtifactUri(artifactUri);
        when(dockerClient.dockerInstalled()).thenReturn(true);
        when(dockerClient.pullImage(image)).thenReturn(true);

        DockerImageDownloader downloader = new DockerImageDownloader(TEST_COMPONENT_ID,
                ComponentArtifact.builder().artifactUri(artifactUri).build(), artifactDir, dockerClient, ecrAccessor);
        downloader.setRetryConfig(retryConfig);

        downloader.download();

        assertEquals("alpine", image.getName());
        assertEquals("latest", image.getTag());
        assertNull(image.getDigest());
        assertFalse(image.getRegistry().isEcrRegistry());
        assertFalse(image.getRegistry().isPrivateRegistry());
        assertEquals("registry.hub.docker.com/library", image.getRegistry().getEndpoint());

        verify(ecrAccessor, never()).getCredentials(anyString());
        verify(dockerClient, never()).login(any());
        verify(dockerClient).pullImage(image);
    }
}

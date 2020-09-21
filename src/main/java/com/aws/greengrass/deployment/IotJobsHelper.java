/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 */

package com.aws.greengrass.deployment;

import com.aws.greengrass.dependency.InjectionActions;
import com.aws.greengrass.deployment.exceptions.AWSIotException;
import com.aws.greengrass.deployment.exceptions.ConnectionUnavailableException;
import com.aws.greengrass.deployment.exceptions.DeviceConfigurationException;
import com.aws.greengrass.deployment.model.Deployment;
import com.aws.greengrass.deployment.model.Deployment.DeploymentType;
import com.aws.greengrass.deployment.model.DeploymentTaskMetadata;
import com.aws.greengrass.lifecyclemanager.GreengrassService;
import com.aws.greengrass.lifecyclemanager.Kernel;
import com.aws.greengrass.lifecyclemanager.exceptions.ServiceLoadException;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.mqttclient.MqttClient;
import com.aws.greengrass.mqttclient.WrapperMqttClientConnection;
import com.aws.greengrass.util.Coerce;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import software.amazon.awssdk.crt.mqtt.MqttClientConnection;
import software.amazon.awssdk.crt.mqtt.MqttClientConnectionEvents;
import software.amazon.awssdk.crt.mqtt.MqttException;
import software.amazon.awssdk.crt.mqtt.QualityOfService;
import software.amazon.awssdk.iot.iotjobs.IotJobsClient;
import software.amazon.awssdk.iot.iotjobs.model.DescribeJobExecutionRequest;
import software.amazon.awssdk.iot.iotjobs.model.DescribeJobExecutionResponse;
import software.amazon.awssdk.iot.iotjobs.model.DescribeJobExecutionSubscriptionRequest;
import software.amazon.awssdk.iot.iotjobs.model.JobExecutionData;
import software.amazon.awssdk.iot.iotjobs.model.JobExecutionSummary;
import software.amazon.awssdk.iot.iotjobs.model.JobExecutionsChangedEvent;
import software.amazon.awssdk.iot.iotjobs.model.JobExecutionsChangedSubscriptionRequest;
import software.amazon.awssdk.iot.iotjobs.model.JobStatus;
import software.amazon.awssdk.iot.iotjobs.model.RejectedError;
import software.amazon.awssdk.iot.iotjobs.model.UpdateJobExecutionRequest;
import software.amazon.awssdk.iot.iotjobs.model.UpdateJobExecutionSubscriptionRequest;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Supplier;
import javax.inject.Inject;
import javax.inject.Named;

import static com.aws.greengrass.deployment.DeploymentService.DEPLOYMENTS_QUEUE;
import static com.aws.greengrass.deployment.DeploymentService.OBJECT_MAPPER;
import static com.aws.greengrass.deployment.DeploymentStatusKeeper.PERSISTED_DEPLOYMENT_STATUS_KEY_DEPLOYMENT_TYPE;
import static com.aws.greengrass.deployment.DeploymentStatusKeeper.PERSISTED_DEPLOYMENT_STATUS_KEY_JOB_ID;
import static com.aws.greengrass.deployment.DeploymentStatusKeeper.PERSISTED_DEPLOYMENT_STATUS_KEY_JOB_STATUS;
import static com.aws.greengrass.deployment.DeploymentStatusKeeper.PERSISTED_DEPLOYMENT_STATUS_KEY_STATUS_DETAILS;

@NoArgsConstructor
public class IotJobsHelper implements InjectionActions {

    protected static final String UPDATE_SPECIFIC_JOB_ACCEPTED_TOPIC =
            "$aws/things/{thingName}/jobs/{jobId}/update/accepted";
    protected static final String UPDATE_SPECIFIC_JOB_REJECTED_TOPIC =
            "$aws/things/{thingName}/jobs/{jobId}/update/rejected";
    public static final String UPDATE_DEPLOYMENT_STATUS_TIMEOUT_ERROR_LOG = "Timed out while updating the job status";
    public static final String UPDATE_DEPLOYMENT_STATUS_MQTT_ERROR_LOG = "Caught exception while updating job status";
    public static final String UPDATE_DEPLOYMENT_STATUS_ACCEPTED = "Job status update was accepted";

    //The time within which device expects an acknowledgement from Iot cloud after publishing an MQTT message
    //This value needs to be revisited and set to more realistic numbers
    private static final long TIMEOUT_FOR_RESPONSE_FROM_IOT_CLOUD_SECONDS = Duration.ofMinutes(5).getSeconds();
    //The time it takes for device to publish a message
    //This value needs to be revisited and set to more realistic numbers
    private static final long TIMEOUT_FOR_IOT_JOBS_OPERATIONS_SECONDS = Duration.ofMinutes(1).getSeconds();

    private static final String JOB_ID_LOG_KEY_NAME = "JobId";
    public static final String STATUS_LOG_KEY_NAME = "Status";
    // Sometimes when we are notified that a new job is queued and request the next pending job document immediately,
    // we get an empty response. This unprocessedJobs is to track the number of new queued jobs that we are notified
    // with, and keep retrying the request until we get a non-empty response.
    private static final AtomicInteger unprocessedJobs = new AtomicInteger(0);
    private static final LatestQueuedJobs latestQueuedJobs = new LatestQueuedJobs();

    private static final Logger logger = LogManager.getLogger(IotJobsHelper.class);

    @Inject
    private DeviceConfiguration deviceConfiguration;

    @Inject
    private IotJobsClientFactory iotJobsClientFactory;

    @Inject
    private WrapperMqttConnectionFactory wrapperMqttConnectionFactory;

    @Inject
    private ExecutorService executorService;

    @Inject
    private DeploymentStatusKeeper deploymentStatusKeeper;

    @Inject
    private Kernel kernel;

    @Inject
    private MqttClient mqttClient;

    @Setter
    @Inject
    @Named(DEPLOYMENTS_QUEUE)
    private LinkedBlockingQueue<Deployment> deploymentsQueue;

    private final AtomicBoolean receivedShutdown = new AtomicBoolean(false);
    private final AtomicBoolean postInjectInProgress = new AtomicBoolean(false);

    private IotJobsClient iotJobsClient;
    private MqttClientConnection connection;

    private final Consumer<JobExecutionsChangedEvent> eventHandler = event -> {
        /*
         * This message is received when either of these things happen
         * 1. Last job completed (successful/failed)
         * 2. A new job was queued
         * 3. A job was cancelled
         * This message receives the list of Queued and InProgress jobs at the time of this message
         */
        Map<JobStatus, List<JobExecutionSummary>> jobs = event.jobs;
        if (jobs.containsKey(JobStatus.QUEUED)) {
            // Only increment instead of adding number of jobs from the list, because we will get one notification for
            // each new job QUEUED.
            unprocessedJobs.incrementAndGet();
            logger.atInfo().log("Received new deployment notification. Requesting details");
            //Do not wait on the future in this async handler,
            //as it will block the thread which establishes
            // the MQTT connection. This will result in frozen MQTT connection
            requestNextPendingJobDocument();
            return;
        }
        if (jobs.isEmpty()) {
            logger.atInfo().log("Received empty jobs in notification ");
            evaluateCancellationAndCancelDeploymentIfNeeded();
            return;
        }
        logger.atInfo().kv("jobs", jobs).log("Received other deployment notification. Not supported yet");
    };

    /**
     * Handler that gets invoked when a job description is received.
     * Next pending job description is requested when an mqtt message
     * is published using {@Code requestNextPendingJobDocument} in {@link IotJobsHelper}
     */
    private final Consumer<DescribeJobExecutionResponse> describeJobExecutionResponseConsumer = response -> {
        if (response.execution == null) {
            logger.atInfo().log("No deployment job found");
            if (unprocessedJobs.get() > 0) {
                // Keep resending request for job details since we got notification of QUEUED jobs
                logger.atDebug().log("Retry requesting next pending job document");
                requestNextPendingJobDocument();
            }
            return;
        }
        unprocessedJobs.decrementAndGet();
        JobExecutionData jobExecutionData = response.execution;

        logger.atInfo().kv(JOB_ID_LOG_KEY_NAME, jobExecutionData.jobId).kv(STATUS_LOG_KEY_NAME, jobExecutionData.status)
                .kv("queueAt", jobExecutionData.queuedAt).log("Received Iot job description");
        if (!latestQueuedJobs.addIfAbsent(jobExecutionData.queuedAt.toInstant(), jobExecutionData.jobId)) {
            logger.atInfo().kv(JOB_ID_LOG_KEY_NAME, jobExecutionData.jobId)
                    .log("Duplicate or outdated job notification. Ignoring.");
            return;
        }

        String documentString;
        try {
            documentString = OBJECT_MAPPER.writeValueAsString(jobExecutionData.jobDocument);
        } catch (JsonProcessingException e) {
            //TODO: Handle when job document is incorrect json.
            // This should not happen as we are converting a HashMap
            return;
        }

        // Reaching this point means there is no IN_PROGRESS job in cloud because if there was, it would
        // have been deduplicated. The fact that we got the next queued deployment means that the previous
        // IN_PROGRESS job is either finished with SUCCEEDED/FAILED status or got cancelled
        // Hence, evaluate if there was a cancellation and if so add a cancellation deployment and
        // then add this next QUEUED job to the deployment queue
        evaluateCancellationAndCancelDeploymentIfNeeded();

        // Add the job queued in cloud to the deployment queue so it's picked up on its turn
        Deployment deployment =
                new Deployment(documentString, DeploymentType.IOT_JOBS, jobExecutionData.jobId);

        if (!deploymentsQueue.contains(deployment) && deploymentsQueue.offer(deployment)) {
            logger.atInfo().kv(JOB_ID_LOG_KEY_NAME, jobExecutionData.jobId).log("Added the job to the queue");
        }
    };


    @Getter
    public MqttClientConnectionEvents callbacks = new MqttClientConnectionEvents() {
        @Override
        public void onConnectionInterrupted(int errorCode) {
        }

        @Override
        public void onConnectionResumed(boolean sessionPresent) {
            executorService.execute(() -> {
                subscribeToJobsTopics();
                deploymentStatusKeeper.publishPersistedStatusUpdates(DeploymentType.IOT_JOBS);
            });
        }
    };

    /**
     * Constructor for unit testing.
     *
     */
    IotJobsHelper(DeviceConfiguration deviceConfiguration,
                  IotJobsClientFactory iotJobsClientFactory,
                  LinkedBlockingQueue<Deployment> deploymentsQueue,
                  DeploymentStatusKeeper deploymentStatusKeeper,
                  ExecutorService executorService,
                  Kernel kernel,
                  WrapperMqttConnectionFactory wrapperMqttConnectionFactory,
                  MqttClient mqttClient) {
        this.deviceConfiguration = deviceConfiguration;
        this.iotJobsClientFactory = iotJobsClientFactory;
        this.deploymentsQueue = deploymentsQueue;
        this.deploymentStatusKeeper = deploymentStatusKeeper;
        this.executorService = executorService;
        this.kernel = kernel;
        this.wrapperMqttConnectionFactory = wrapperMqttConnectionFactory;
        this.mqttClient = mqttClient;
    }

    @Override
    @SuppressFBWarnings
    public void postInject() {
        try {
            deviceConfiguration.validate();
        } catch (DeviceConfigurationException e) {
            // TODO: If the device configurations are updated later, while the kernel is running,
            //  then device should attempt to connect to AWS Iot cloud again
            logger.atWarn().log("Device not configured to talk to AWS Iot cloud. Device will run in offline mode");
            return;
        }
        mqttClient.addToCallbackEvents(callbacks);
        this.connection = wrapperMqttConnectionFactory.getAwsIotMqttConnection(mqttClient);
        this.iotJobsClient = iotJobsClientFactory.getIotJobsClient(connection);
        logger.dfltKv("ThingName", (Supplier<String>) () ->
                Coerce.toString(deviceConfiguration.getThingName()));
        subscribeToJobsTopics();
        logger.atInfo().log("Connection established to Iot cloud");
        deploymentStatusKeeper.registerDeploymentStatusConsumer(DeploymentType.IOT_JOBS,
                this::deploymentStatusChanged, IotJobsHelper.class.getName());
    }

    public static class WrapperMqttConnectionFactory {
        public WrapperMqttClientConnection getAwsIotMqttConnection(MqttClient mqttClient) {
            return new WrapperMqttClientConnection(mqttClient);
        }
    }

    public static class IotJobsClientFactory {
        public IotJobsClient getIotJobsClient(MqttClientConnection connection) {
            return new IotJobsClient(connection);
        }
    }

    private Boolean deploymentStatusChanged(Map<String, Object> deploymentDetails) {
        DeploymentDetailsIotJobs deploymentDetailsIotJobs = OBJECT_MAPPER.convertValue(deploymentDetails,
                DeploymentDetailsIotJobs.class);
        String jobId = deploymentDetailsIotJobs.getJobId();
        String status = deploymentDetailsIotJobs.getJobStatus().toString();
        Map<String, String> statusDetails = deploymentDetailsIotJobs.getStatusDetails();
        logger.atInfo().kv(JOB_ID_LOG_KEY_NAME, jobId).kv(STATUS_LOG_KEY_NAME, status).kv("StatusDetails",
                statusDetails).log("Updating status of persisted deployment");
        try {
            updateJobStatus(jobId, JobStatus.valueOf(status), new HashMap<>(statusDetails));
            return true;
        } catch (ExecutionException e) {
            if (e.getCause() instanceof MqttException) {
                //caused due to connectivity issue
                logger.atWarn().setCause(e).kv(STATUS_LOG_KEY_NAME, status)
                        .log(UPDATE_DEPLOYMENT_STATUS_MQTT_ERROR_LOG);
                return false;
            }
            // This happens when job status update gets rejected from the Iot Cloud
            // Want to remove this job from the list and continue updating others
            logger.atError().kv(STATUS_LOG_KEY_NAME, status).kv(JOB_ID_LOG_KEY_NAME, jobId).setCause(e)
                    .log("Job status update rejected");
            return true;
        } catch (TimeoutException e) {
            // assuming this is due to network issue
            logger.info(UPDATE_DEPLOYMENT_STATUS_TIMEOUT_ERROR_LOG);
        } catch (InterruptedException e) {
            logger.atWarn().kv(JOB_ID_LOG_KEY_NAME, jobId).kv(STATUS_LOG_KEY_NAME, status)
                    .log("Got interrupted while updating the job status");
        }
        return false;
    }

    /**
     * Subscribes to the topic which receives confirmation message of Job update for a given JobId.
     * Updates the status of an Iot Job with given JobId to a given status.
     *
     * @param jobId            The jobId to be updated
     * @param status           The {@link JobStatus} to which to update
     * @param statusDetailsMap map with job status details
     * @throws ExecutionException   if update fails
     * @throws InterruptedException if the thread gets interrupted
     * @throws TimeoutException     if the operation does not complete within the given time
     */
    @SuppressWarnings("PMD.LooseCoupling")
    public void updateJobStatus(String jobId, JobStatus status, HashMap<String, String> statusDetailsMap)
            throws ExecutionException, InterruptedException, TimeoutException {
        UpdateJobExecutionSubscriptionRequest subscriptionRequest = new UpdateJobExecutionSubscriptionRequest();
        String thingName = Coerce.toString(deviceConfiguration.getThingName());
        subscriptionRequest.thingName = thingName;
        subscriptionRequest.jobId = jobId;
        CompletableFuture<Void> gotResponse = new CompletableFuture<>();
        iotJobsClient.SubscribeToUpdateJobExecutionAccepted(subscriptionRequest, QualityOfService.AT_LEAST_ONCE,
                (response) -> {
                    logger.atInfo().kv(JOB_ID_LOG_KEY_NAME, jobId).kv(STATUS_LOG_KEY_NAME, status)
                            .log(UPDATE_DEPLOYMENT_STATUS_ACCEPTED);
                    gotResponse.complete(null);
                });

        iotJobsClient.SubscribeToUpdateJobExecutionRejected(subscriptionRequest, QualityOfService.AT_LEAST_ONCE,
                (response) -> {
                    logger.atWarn().kv(JOB_ID_LOG_KEY_NAME, jobId).kv(STATUS_LOG_KEY_NAME, status)
                            .log("Job status updated rejected");
                    //TODO: Can this be due to duplicate messages being sent for the job?
                    gotResponse.completeExceptionally(new Exception(response.message));
                });

        UpdateJobExecutionRequest updateJobRequest = new UpdateJobExecutionRequest();
        updateJobRequest.jobId = jobId;
        updateJobRequest.status = status;
        updateJobRequest.statusDetails = statusDetailsMap;
        updateJobRequest.thingName = thingName;
        try {
            iotJobsClient.PublishUpdateJobExecution(updateJobRequest, QualityOfService.AT_LEAST_ONCE).get();
        } catch (ExecutionException e) {
            gotResponse.completeExceptionally(e.getCause());
        }

        try {
            gotResponse.get(TIMEOUT_FOR_RESPONSE_FROM_IOT_CLOUD_SECONDS, TimeUnit.SECONDS);
        } finally {
            // Either got response, or timed out, so unsubscribe from the job topics now
            String rejectTopicForJobId =
                    UPDATE_SPECIFIC_JOB_REJECTED_TOPIC.replace("{thingName}", thingName).replace("{jobId}", jobId);
            connection.unsubscribe(rejectTopicForJobId);
            String acceptTopicForJobId =
                    UPDATE_SPECIFIC_JOB_ACCEPTED_TOPIC.replace("{thingName}", thingName).replace("{jobId}", jobId);
            connection.unsubscribe(acceptTopicForJobId);
        }
    }

    /**
     * Request the job description of the next available job for this Iot Thing.
     * It publishes on the $aws/things/{thingName}/jobs/$next/get topic.
     */
    public void requestNextPendingJobDocument() {
        DescribeJobExecutionRequest describeJobExecutionRequest = new DescribeJobExecutionRequest();
        describeJobExecutionRequest.thingName = Coerce.toString(deviceConfiguration.getThingName());
        describeJobExecutionRequest.jobId = "$next";
        describeJobExecutionRequest.includeJobDocument = true;
        //This method is specifically called from an async event notification handler. Async handler cannot block on
        // this future as that will freeze the MQTT connection.
        iotJobsClient.PublishDescribeJobExecution(describeJobExecutionRequest, QualityOfService.AT_LEAST_ONCE);
        logger.atDebug().log("Requesting the next deployment");
    }


    /**
     * Subscribe to the mqtt topics needed for getting Iot Jobs notifications.
     *
     * @throws InterruptedException           When operation is interrupted
     * @throws AWSIotException                When there is an exception from the Iot cloud
     * @throws ConnectionUnavailableException When connection to cloud is not available
     *
     */
    public void subscribeToJobsTopics()   {
        try {
            //TODO: Add retry in case of Throttling, Timeout and LimitExceed exception
            subscribeToEventNotifications(eventHandler);
            subscribeToGetNextJobDescription(describeJobExecutionResponseConsumer, rejectedError -> {
                logger.error("Job subscription got rejected", rejectedError);
                //TODO: Add retry logic for subscribing
            });
            requestNextPendingJobDocument();
        } catch (ExecutionException e) {
            //TODO: If network is not available then it will throw MqttException
            // If there is any other problem like thingName is not specified in the request then also
            // it throws Mqtt exception. Need to distinguish between what is cause due to network unavailability
            // and what is caused by other non-transient causes like invalid parameters
            if (e.getCause() instanceof MqttException) {
                logger.atWarn().setCause(e).log("No connection available during subscribing to topic. "
                        + "Will retry when connection is available");
                return;
            }
            //Device will run in offline mode if it is not able to subscribe to Iot Jobs topics
            logger.atError().setCause(e).log("Caught exception while subscribing to Iot Jobs topics");
        } catch (TimeoutException e) {
            //After the max retries have been exhausted
            logger.atWarn().setCause(e).log("No connection available during subscribing to topic. "
                    + "Will retry when connection is available");
        } catch (InterruptedException e) {
            //Since this method can run as runnable cannot throw exception so handling exceptions here
            logger.atWarn().log("Interrupted while running deployment service");
        }
    }

    /**
     * Subscribes to the describe job topic to get the job details for the next available pending job
     * It also publishes a message to get the next pending job.
     * It returns an empty message if nothing is available
     *
     * @param consumerAccept Consumer for when the job is accepted
     * @param consumerReject Consumer for when the job is rejected
     * @throws ExecutionException   if subscribing fails
     * @throws InterruptedException if the thread gets interrupted
     * @throws TimeoutException     if the operation does not complete within the given time
     */
    protected void subscribeToGetNextJobDescription(Consumer<DescribeJobExecutionResponse> consumerAccept,
                                                    Consumer<RejectedError> consumerReject)
            throws ExecutionException, InterruptedException, TimeoutException {

        logger.atInfo().log("Subscribing to deployment job execution update.");
        DescribeJobExecutionSubscriptionRequest describeJobExecutionSubscriptionRequest =
                new DescribeJobExecutionSubscriptionRequest();
        describeJobExecutionSubscriptionRequest.thingName = Coerce.toString(deviceConfiguration.getThingName());
        describeJobExecutionSubscriptionRequest.jobId = "$next";
        CompletableFuture<Integer> subscribed = iotJobsClient
                .SubscribeToDescribeJobExecutionAccepted(describeJobExecutionSubscriptionRequest,
                        QualityOfService.AT_LEAST_ONCE, consumerAccept);
        subscribed.get(TIMEOUT_FOR_IOT_JOBS_OPERATIONS_SECONDS, TimeUnit.SECONDS);
        subscribed = iotJobsClient.SubscribeToDescribeJobExecutionRejected(describeJobExecutionSubscriptionRequest,
                QualityOfService.AT_LEAST_ONCE, consumerReject);
        subscribed.get(TIMEOUT_FOR_IOT_JOBS_OPERATIONS_SECONDS, TimeUnit.SECONDS);
        logger.atInfo().log("Subscribed to deployment job execution update.");
    }

    /**
     * Subscribe to $aws/things/{thingName}/jobs/notify topic.
     *
     * @param eventHandler The handler which run when an event is received
     * @throws ExecutionException   When subscribe failed with an exception
     * @throws InterruptedException When this thread was interrupted
     * @throws TimeoutException     if the operation does not complete within the given time
     */
    protected void subscribeToEventNotifications(Consumer<JobExecutionsChangedEvent> eventHandler)
            throws ExecutionException, InterruptedException, TimeoutException {
        logger.atInfo().log("Subscribing to deployment job event notifications.");
        JobExecutionsChangedSubscriptionRequest request = new JobExecutionsChangedSubscriptionRequest();
        request.thingName = Coerce.toString(deviceConfiguration.getThingName());
        CompletableFuture<Integer> subscribed = iotJobsClient
                .SubscribeToJobExecutionsChangedEvents(request, QualityOfService.AT_LEAST_ONCE, eventHandler);
        subscribed.get(TIMEOUT_FOR_IOT_JOBS_OPERATIONS_SECONDS, TimeUnit.SECONDS);
        logger.atInfo().log("Subscribed to deployment job event notifications.");
    }

    private void evaluateCancellationAndCancelDeploymentIfNeeded() {
        try {
            GreengrassService deploymentServiceLocateResult =
                    kernel.locate(DeploymentService.DEPLOYMENT_SERVICE_TOPICS);
            if (deploymentServiceLocateResult instanceof DeploymentService) {
                DeploymentService deploymentService = (DeploymentService) deploymentServiceLocateResult;
                DeploymentTaskMetadata currentDeployment = deploymentService.getCurrentDeploymentTaskMetadata();

                // If the queue is not empty then it means deployment(s) from other sources is/are queued in it,
                // in that case don't add a cancellation deployment because it can't be added to the front of the queue
                // we will just have to let current deployment finish
                Deployment deployment = new Deployment(DeploymentType.IOT_JOBS, UUID.randomUUID().toString(), true);
                if (deploymentsQueue.isEmpty() && currentDeployment != null && currentDeployment.isCancellable()
                        && DeploymentType.IOT_JOBS.equals(currentDeployment.getDeploymentType())
                        && deploymentsQueue.offer(deployment)) {
                    logger.atInfo().log("Added cancellation deployment to the queue");
                }
            }
        } catch (ServiceLoadException e) {
            logger.atError().setCause(e).log("Failed to find deployment service");
        }
    }

    private static class LatestQueuedJobs {
        private Instant lastQueueAt = Instant.EPOCH;
        private final Set<String> jobIds = new HashSet<>();

        /**
         * Track IoT jobs with the latest timestamp.
         *
         * @param queueAt QueueAt timestamp in IoT Job Execution Data
         * @param jobId IoT job ID
         * @return true if IoT job with the given ID is a new job yet to be processed, false otherwise
         */
        public synchronized boolean addIfAbsent(Instant queueAt, String jobId) {
            if (queueAt.isAfter(lastQueueAt)) {
                lastQueueAt = queueAt;
                jobIds.clear();
                jobIds.add(jobId);
                return true;
            }
            if (queueAt.isBefore(lastQueueAt) || jobIds.contains(jobId)) {
                return false;
            }
            jobIds.add(jobId);
            return true;
        }
    }

    @Data
    public static class DeploymentDetailsIotJobs {
        @JsonProperty(PERSISTED_DEPLOYMENT_STATUS_KEY_JOB_ID)
        private String jobId;
        @JsonProperty(PERSISTED_DEPLOYMENT_STATUS_KEY_JOB_STATUS)
        private JobStatus jobStatus;
        @JsonProperty(PERSISTED_DEPLOYMENT_STATUS_KEY_STATUS_DETAILS)
        private Map<String, String> statusDetails;
        @JsonProperty(PERSISTED_DEPLOYMENT_STATUS_KEY_DEPLOYMENT_TYPE)
        private DeploymentType deploymentType;

        /**
         * Returns a map of string to object representing the deployment details.
         * @return Map of string to object
         */
        public Map<String, Object> convertToMapOfObjects() {
            Map<String, Object> deploymentDetails = new HashMap<>();
            deploymentDetails.put(PERSISTED_DEPLOYMENT_STATUS_KEY_JOB_ID, jobId);
            deploymentDetails.put(PERSISTED_DEPLOYMENT_STATUS_KEY_JOB_STATUS, jobStatus);
            deploymentDetails.put(PERSISTED_DEPLOYMENT_STATUS_KEY_STATUS_DETAILS, statusDetails);
            deploymentDetails.put(PERSISTED_DEPLOYMENT_STATUS_KEY_DEPLOYMENT_TYPE, deploymentType);
            return deploymentDetails;
        }
    }
}
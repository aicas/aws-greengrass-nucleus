/* Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 */

package com.aws.iot.evergreen.kernel;

import com.aws.iot.evergreen.config.Topics;
import com.aws.iot.evergreen.dependency.Crashable;
import com.aws.iot.evergreen.dependency.ImplementsService;
import com.aws.iot.evergreen.dependency.State;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.inject.Singleton;

/**
 * Handles requests to update the system's configuration during safe times.
 * (or anything else that's disruptive and shouldn't be done until the system
 * is in a "safe" state).
 *
 * <p>It maintains two lists: one is a list of actions that will be executed when the
 * system is next "disruptable".  This is typically code that is going to install an update.
 *
 * <p>The other is a list of functions that are called to check if the system is "disruptable".
 * For example, a TV might not be disruptable if it is being used, or a robot if it is
 * in motion.
 *
 * <p>If the update service is periodic, update actions will only be processed at that time.
 * Otherwise, it the update will be processed immediately, assuming that all disruptability
 * checks pass.
 */
@ImplementsService(name = "SafeSystemUpdate", autostart = true)
@Singleton
public class UpdateSystemSafelyService extends EvergreenService {
    private final LinkedHashMap<String, Crashable> pendingActions = new LinkedHashMap<>();
    private final CopyOnWriteArrayList<DisruptableCheck> disruptableChecks = new CopyOnWriteArrayList<>();

    public UpdateSystemSafelyService(Topics c) {
        super(c);
    }

    public void addDisruptableCheck(DisruptableCheck d) {
        disruptableChecks.add(d);
    }

    public void removeDisruptableCheck(DisruptableCheck d) {
        disruptableChecks.remove(d);
    }

    /**
     * Add an update action to be performed when the system is in a "safe" state.
     *
     * @param tag    used both as a printable description and a de-duplication key.  eg. If
     *               the action is installing a new config file, the tag should probably be the
     *               URL of the config.  If a key is duplicated by subsequent actions, they
     *               are suppressed.
     * @param action The action to be performed.
     */
    public synchronized void addUpdateAction(String tag, Crashable action) {
        pendingActions.put(tag, action);
        logger.atDebug().setEventType("register-service-update-action").addKeyValue("action", tag).log();
        if (!isPeriodic()) {
            requestStart();
        }
    }

    protected synchronized void runUpdateActions() {
        for (Map.Entry<String, Crashable> todo : pendingActions.entrySet()) {
            try {
                todo.getValue().run();
                logger.atDebug().setEventType("service-update-action").addKeyValue("action", todo.getKey()).log();
            } catch (Throwable t) {
                logger.atError().setEventType("service-update-action-error").addKeyValue("action", todo.getKey())
                        .setCause(t).log();
            }
        }
        pendingActions.clear();
        for (DisruptableCheck c : disruptableChecks) {
            c.disruptionCompleted(); // Notify disruption is over
        }
    }

    @SuppressWarnings({"SleepWhileInLoop", "checkstyle:emptycatchblock"})
    @Override
    public void startup() {
        // startup() is invoked on it's own thread
        reportState(State.RUNNING);
        logger.atInfo().setEventType("check-available-service-update").log();

        while (!pendingActions.isEmpty()) {
            // TODO: should really use an injected clock to support simulation-time
            //      it's a big project and would affect many parts of the system.
            final long now = System.currentTimeMillis();
            long maxt = now;

            logger.atDebug().setEventType("service-update-pending").addKeyValue("numOfUpdates", pendingActions.size())
                    .log();
            for (DisruptableCheck c : disruptableChecks) {
                long ct = c.whenIsDisruptionOK();
                if (ct > maxt) {
                    maxt = ct;
                }
            }
            if (maxt > now) {
                try {
                    logger.atDebug().setEventType("service-update-pending").addKeyValue("waitInMS",
                            maxt - now).log();
                    Thread.sleep(maxt - now);
                } catch (InterruptedException ignored) {
                }
            } else {
                logger.atDebug().setEventType("service-update-scheduled").log();
                context.runOnPublishQueueAndWait(() -> {
                    logger.atInfo().setEventType("service-update-start").log();
                    runUpdateActions();
                    logger.atInfo().setEventType("service-update-finish").log();
                });
            }
        }
        this.requestStop();
    }

    public interface DisruptableCheck {
        /**
         * Inform a listener that a disruption is pending to find out when a disruption
         * is acceptable.
         *
         * @return Estimated time when this handler will be willing to be disrupted,
         *     expressed as milliseconds since the epoch. If
         *     the returned value is less than now (System.currentTimeMillis()) the handler
         *     is granting permission to be disrupted.  Otherwise, it will be asked again
         *     sometime later.
         */
        long whenIsDisruptionOK();

        /**
         * After a disruption, this is called to signal to the handler that the
         * disruption is over and it's OK to start activity.
         */
        void disruptionCompleted();
    }
}
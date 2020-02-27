/* Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 */

package com.aws.iot.evergreen.kernel;

import com.aws.iot.evergreen.config.Node;
import com.aws.iot.evergreen.config.Topic;
import com.aws.iot.evergreen.config.Topics;
import com.aws.iot.evergreen.dependency.State;
import com.aws.iot.evergreen.ipc.AuthHandler;
import com.aws.iot.evergreen.util.Coerce;
import com.aws.iot.evergreen.util.Exec;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.function.IntConsumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GenericExternalService extends EvergreenService {
    static final String[] sigCodes =
            {"SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGIOT", "SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1",
                    "SIGSEGV", "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGSTKFLT", "SIGCHLD", "SIGCONT", "SIGSTOP",
                    "SIGTSTP", "SIGTTIN", "SIGTTOU", "SIGURG", "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH",
                    "SIGIO", "SIGPWR", "SIGSYS",};
    private static final Pattern skipcmd = Pattern.compile("(exists|onpath) +(.+)");
    private boolean inShutdown;
    private Exec currentScript;

    /**
     * Create a new GenericExternalService.
     *
     * @param c root topic for this service.
     */
    public GenericExternalService(Topics c) {
        super(c);

        // when configuration reloads and child Topic changes, restart/re-install the service.
        c.subscribe((what, child) -> {
            if (c.parentNeedsToKnow() && !child.childOf("shutdown")) {
                logger.atInfo().setEventType("service-config-change")
                        .addKeyValue("configNode", child.getFullName()).log();
                if (child.childOf("install")) {
                    requestReinstall();
                } else {
                    requestRestart();
                }
            }
        });

        AuthHandler.registerAuthToken(this);
    }

    public static String exit2String(int exitCode) {
        return exitCode > 128 && exitCode < 129 + sigCodes.length ? sigCodes[exitCode - 129]
                : "exit(" + ((exitCode << 24) >> 24) + ")";
    }

    @Override
    public void install() {
        if (run("install", null) == RunStatus.Errored) {
            System.err.println("install errored: " + getName());
            reportState(State.ERRORED);
        }
        super.install();
    }

    @Override
    public void awaitingStartup() {
        run("awaitingStartup", null);
        super.awaitingStartup();
    }

    @Override
    public void startup() {
        RunStatus result = run("startup", exit -> {
            if (getState() == State.INSTALLED) {
                if (exit == 0) {
                    super.startup();
                } else {
                    reportState(State.ERRORED);
                }
            }
        });
        if (result == RunStatus.Errored) {
            reportState(State.ERRORED);
        } else if (result == RunStatus.NothingDone) {
            super.startup();

            if (run("run", exit -> {
                currentScript = null;
                if (!inShutdown) {
                    if (exit == 0) {
                        this.requestStop();
                        logger.atInfo().setEventType("generic-service-stopping")
                                .log("Service finished running.");
                    } else {
                        reportState(State.ERRORED);
                        logger.atError().setEventType("generic-service-errored")
                                .addKeyValue("exitCode", exit).log();
                    }
                }
            }) == RunStatus.NothingDone) {
                logger.atInfo().setEventType("generic-service-finished")
                        .log("Nothing done.");
                this.requestStop();
            }
        }
    }

    @Override
    public void shutdown() {
        inShutdown = true;
        run("shutdown", null);
        Exec e = currentScript;
        if (e != null && e.isRunning()) {
            try {
                e.close();
                //e.waitClosed(1000);
                logger.atInfo().setEventType("generic-service-shutdown").log();
            } catch (IOException ioe) {
                logger.atError().setEventType("generic-service-shutdown-error").setCause(ioe).log();
            }
        }

        inShutdown = false;
    }

    /**
     * Run one of the commands defined in the config on the command line.
     *
     * @param name name of the command to run ("run", "install", "start").
     * @param background IntConsumer to receive the exit code. If null, the command will timeout after 2 minutes.
     * @return the status of the run.
     */
    protected RunStatus run(String name, IntConsumer background) {
        Node n = config.getChild(name);
        return n == null ? RunStatus.NothingDone : run(n, background);
    }

    protected RunStatus run(Node n, IntConsumer background) {
        return n instanceof Topic ? run((Topic) n, background, null)
                : n instanceof Topics ? run((Topics) n, background) : RunStatus.Errored;
    }

    protected RunStatus run(Topic t, IntConsumer background, Topics config) {
        return run(t, Coerce.toString(t.getOnce()), background, config);
    }

    protected RunStatus run(Topic t, String cmd, IntConsumer background, Topics config) {
        final ShellRunner shellRunner = context.get(ShellRunner.class);
        final EZTemplates templateEngine = context.get(EZTemplates.class);
        cmd = templateEngine.rewrite(cmd).toString();
        setStatus(cmd);
        if (background == null) {
            setStatus(null);
        }
        Exec exec = shellRunner.setup(t.getFullName(), cmd, this);
        currentScript = exec;
        if (exec != null) { // there's something to run
            addEnv(exec, t.parent);
            logger.atDebug().setEventType("generic-service-run").log();
            RunStatus ret = shellRunner.successful(exec, cmd, background) ? RunStatus.OK : RunStatus.Errored;
            if (background == null) {
                currentScript = null;
            }
            return ret;
        } else {
            return RunStatus.NothingDone;
        }
    }

    protected RunStatus run(Topics t, IntConsumer background) {
        if (!shouldSkip(t)) {
            Node script = t.getChild("script");
            if (script instanceof Topic) {
                return run((Topic) script, background, t);
            } else {
                logger.atError().setEventType("generic-service-invalid-config").addKeyValue("configNode",
                        t.getFullName()).log("Missing script");
                serviceErrored();
                return RunStatus.Errored;
            }
        } else {
            logger.atDebug().setEventType("generic-service-skipped").addKeyValue("script", t.getFullName()).log();
            return RunStatus.OK;
        }
    }

    boolean shouldSkip(Topics n) {
        Node skipif = n.getChild("skipif");
        boolean neg = skipif == null && (skipif = n.getChild("doif")) != null;
        if (skipif instanceof Topic) {
            Topic tp = (Topic) skipif;
            String expr = String.valueOf(tp.getOnce()).trim();
            if (expr.startsWith("!")) {
                expr = expr.substring(1).trim();
                neg = !neg;
            }
            expr = context.get(EZTemplates.class).rewrite(expr).toString();
            Matcher m = skipcmd.matcher(expr);
            if (m.matches()) {
                switch (m.group(1)) {
                    case "onpath":
                        return Exec.which(m.group(2)) != null ^ neg; // XOR ?!?!
                    case "exists":
                        return Files.exists(Paths.get(context.get(Kernel.class).deTilde(m.group(2)))) ^ neg;
                    case "true":
                        return !neg;
                    default:
                        logger.atError().setEventType("generic-service-invalid-config").addKeyValue("operator",
                                m.group(1)).log("Unknown operator in skipif");
                        serviceErrored();
                        return false;
                }
            }
            RunStatus status = run(tp, expr, null, n);
            // Assume it's a shell script: test for 0 return code and nothing on stderr
            return neg ^ (status != RunStatus.Errored);
        }
        return false;
    }

    private void addEnv(Exec exec, Topics src) {
        if (src != null) {
            addEnv(exec, src.parent); // add parents contributions first
            Node env = src.getChild("setenv");
            if (env instanceof Topics) {
                EZTemplates templateEngine = context.get(EZTemplates.class);
                ((Topics) env).forEach(n -> {
                    if (n instanceof Topic) {
                        exec.setenv(n.name, templateEngine.rewrite(Coerce.toString(((Topic) n).getOnce())));
                    }
                });
            }
        }
    }
}
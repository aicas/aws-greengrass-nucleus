/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.lifecyclemanager.exceptions;

public class ServiceLoadException extends ServiceException {
    static final long serialVersionUID = -3387516993124229948L;

    public ServiceLoadException(String message) {
        super(message);
    }

    public ServiceLoadException(String message, Throwable cause) {
        super(message, cause);
    }

    public ServiceLoadException(Throwable cause) {
        super(cause);
    }
}

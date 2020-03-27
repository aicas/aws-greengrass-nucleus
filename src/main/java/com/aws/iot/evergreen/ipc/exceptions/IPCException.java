package com.aws.iot.evergreen.ipc.exceptions;

public class IPCException extends Exception {
    static final long serialVersionUID = -3387516993124229948L;

    public IPCException(String message) {
        super(message);
    }

    public IPCException(String message, Throwable cause) {
        super(message, cause);
    }
}

package org.apache.zookeeper.server.quorum.auth;

@SuppressWarnings("serial")
public class AuthException extends Exception {
    public AuthException(String message, Throwable cause) {
        super(message, cause);
    }
}

package org.apache.zookeeper.server.quorum.auth;

import org.apache.zookeeper.Login;
import org.apache.zookeeper.client.ZooKeeperSaslClient;
import org.apache.zookeeper.server.auth.SaslServerCallbackHandler;

import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginException;
import java.io.IOException;

/**
 *
 */
public class QuorumAuth {
    private static final String QUORUM_AUTH_ENABLED = "zookeeper.quorum.auth";
    private static final String KERBEROS_SERVICE_PRINCIPAL = "zookeeper.quorum.auth.kerberos.servicePrincipal";
    private static final String QUORUM_CLIENT_LOGIN_CONTEXT = "zookeeper.quorum.client.loginContext";
    private static final String QUORUM_SERVER_LOGIN_CONTEXT = "zookeeper.quorum.server.loginContext";

    static Login clientLogin = null;
    static Login serverLogin = null;

    public static boolean isEnabled() {
        return Boolean.getBoolean(QUORUM_AUTH_ENABLED);
    }

    static String getServicePrincipal() {
        return System.getProperty(KERBEROS_SERVICE_PRINCIPAL, "zkquorum/localhost");
    }

    synchronized static Login getClientLogin() throws LoginException {
        if (clientLogin == null) {
            String loginContext = System.getProperty(QUORUM_CLIENT_LOGIN_CONTEXT, "QuorumClient");
            clientLogin = new Login(loginContext, new ZooKeeperSaslClient.ClientCallbackHandler(null));
            clientLogin.startThreadIfNeeded();
        }
        return clientLogin;
    }

    synchronized static Login getServerLogin() throws LoginException, IOException {
        if (serverLogin == null) {
            String loginContext = System.getProperty(QUORUM_SERVER_LOGIN_CONTEXT, "QuorumServer");
            SaslServerCallbackHandler saslServerCallbackHandler =
                    new SaslServerCallbackHandler(Configuration.getConfiguration(), loginContext);
            serverLogin = new Login(loginContext, saslServerCallbackHandler);
            serverLogin.startThreadIfNeeded();
        }
        return serverLogin;
    }

    enum Status {
        CONTINUE, SUCCESS, ERROR
    }

    static class Message {
        final Status status;
        final byte[] contents;

        public Message(Status s, byte[] b) {
            status = s;
            contents = b;
        }
    }
}

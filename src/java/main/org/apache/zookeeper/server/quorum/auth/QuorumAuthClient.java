package org.apache.zookeeper.server.quorum.auth;

import org.apache.zookeeper.Login;
import org.apache.zookeeper.client.ZooKeeperSaslClient;
import org.apache.zookeeper.server.auth.KerberosName;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

/**
 *
 */
public class QuorumAuthClient {
    private static final Logger LOG = LoggerFactory.getLogger(QuorumAuthClient.class);

    private final Socket sock;

    public QuorumAuthClient(Socket sock) {
        this.sock = sock;
    }

    public void authenticate() throws AuthException {
        SaslClient sc = null;
        try {
            sc = createSaslClient(QuorumAuth.getClientLogin());
            DataOutputStream dout = new DataOutputStream(sock.getOutputStream());
            DataInputStream din = new DataInputStream(sock.getInputStream());
            byte[] response =
                    (sc.hasInitialResponse() ? sc.evaluateChallenge(new byte[0]) : new byte[0]);
            send(dout, response);
            QuorumAuth.Message msg = receive(din);
            while (!sc.isComplete() &&
                    (msg.status == QuorumAuth.Status.CONTINUE || msg.status == QuorumAuth.Status.SUCCESS)) {
                response = sc.evaluateChallenge(msg.contents);
                if (msg.status == QuorumAuth.Status.SUCCESS) {
                    break;
                } else {
                    send(dout, response);
                    msg = receive(din);
                }
            }
        } catch (SaslException e) {
            throw new AuthException("", e);
        } catch (GSSException e) {
            throw new AuthException("", e);
        } catch (IOException e) {
            throw new AuthException("", e);
        } catch (LoginException e) {
            throw new AuthException("", e);
        } catch (PrivilegedActionException e) {
            throw new AuthException("", e);
        } finally {
            if (sc != null) {
                try {
                    sc.dispose();
                } catch (SaslException e) {
                    LOG.error("SaslClient dispose() failed", e);
                }
            }
        }
    }

    private QuorumAuth.Message receive(DataInputStream din) throws IOException {
        // TODO: custom encoding should be replaced by 3rd party messaging format (jute, protobuf).
        int si = din.readInt();
        QuorumAuth.Status s = QuorumAuth.Status.values()[si];
        int len = din.readInt();
        byte[] b = new byte[len];
        if (len > 0) {
            din.readFully(b);
        }
        return new QuorumAuth.Message(s, b);
    }

    private void send(DataOutputStream dout, byte[] response) throws IOException {
        // TODO: custom encoding should be replaced by 3rd party messaging format (jute, protobuf).
        if (response != null && response.length < 0) {
            throw new IOException("Response length < 0");
        }
        dout.writeInt(response.length);
        dout.write(response);
        dout.flush();
    }

    private SaslClient createSaslClient(final Login login) throws LoginException, PrivilegedActionException, SaslException, GSSException {
        // This code is copied from ZooKeeperSaslClient.
        Subject subject = login.getSubject();
        SaslClient saslClient;
        // Use subject.getPrincipals().isEmpty() as an indication of which SASL mechanism to use:
        // if empty, use DIGEST-MD5; otherwise, use GSSAPI.
        if (subject.getPrincipals().isEmpty()) {
            // no principals: must not be GSSAPI: use DIGEST-MD5 mechanism instead.
            LOG.info("Client will use DIGEST-MD5 as SASL mechanism.");
            String[] mechs = {"DIGEST-MD5"};
            String username = (String) (subject.getPublicCredentials().toArray()[0]);
            String password = (String) (subject.getPrivateCredentials().toArray()[0]);
            // "zk-sasl-md5" is a hard-wired 'domain' parameter shared with zookeeper server code (see ServerCnxnFactory.java)
            saslClient = Sasl.createSaslClient(mechs, username, "zookeeper-quorum", "zk-quorum-sasl-md5", null, new ZooKeeperSaslClient.ClientCallbackHandler(password));
            return saslClient;
        } else { // GSSAPI.
            boolean usingNativeJgss =
                    Boolean.getBoolean("sun.security.jgss.native");
            if (usingNativeJgss) {
                // http://docs.oracle.com/javase/6/docs/technotes/guides/security/jgss/jgss-features.html
                // """
                // In addition, when performing operations as a particular
                // Subject, e.g. Subject.doAs(...) or Subject.doAsPrivileged(...),
                // the to-be-used GSSCredential should be added to Subject's
                // private credential set. Otherwise, the GSS operations will
                // fail since no credential is found.
                // """
                GSSManager manager = GSSManager.getInstance();
                Oid krb5Mechanism = new Oid("1.2.840.113554.1.2.2");
                GSSCredential cred = manager.createCredential(null,
                        GSSContext.DEFAULT_LIFETIME,
                        krb5Mechanism,
                        GSSCredential.INITIATE_ONLY);
                subject.getPrivateCredentials().add(cred);
            }
            final Object[] principals = subject.getPrincipals().toArray();
            // determine client principal from subject.
            final Principal clientPrincipal = (Principal) principals[0];
            final KerberosName clientKerberosName = new KerberosName(clientPrincipal.getName());
            // assume that server and client are in the same realm (by default; unless the system property
            // "zookeeper.server.realm" is set).
            String serverRealm = System.getProperty("zookeeper.server.realm", clientKerberosName.getRealm());
            LOG.info("serverRealm: {}", serverRealm);
            KerberosName serviceKerberosName = new KerberosName(QuorumAuth.getServicePrincipal() + "@" + serverRealm);
            final String serviceName = serviceKerberosName.getServiceName();
            final String serviceHostname = serviceKerberosName.getHostName();
            final String clientPrincipalName = clientKerberosName.toString();
            saslClient = Subject.doAs(subject, new PrivilegedExceptionAction<SaslClient>() {
                public SaslClient run() throws SaslException {
                    LOG.info("Client will use GSSAPI as SASL mechanism.");
                    String[] mechs = {"GSSAPI"};
                    LOG.info("creating sasl client: client=" + clientPrincipalName + ";service=" + serviceName + ";serviceHostname=" + serviceHostname);
                    SaslClient saslClient = Sasl.createSaslClient(mechs, clientPrincipalName, serviceName, serviceHostname, null, new ZooKeeperSaslClient.ClientCallbackHandler(null));
                    return saslClient;
                }
            });
            return saslClient;
        }
    }
}

package org.apache.zookeeper.server.quorum.auth;

import org.apache.zookeeper.Login;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
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
public class QuorumAuthServer {
    private static final Logger LOG = LoggerFactory.getLogger(QuorumAuthServer.class);

    private final Socket sock;

    public QuorumAuthServer(Socket sock) {
        this.sock = sock;
    }

    public void authenticate() throws AuthException {
        SaslServer ss = null;
        try {
            ss = createSaslServer(QuorumAuth.getServerLogin());
            DataOutputStream dout = new DataOutputStream(sock.getOutputStream());
            DataInputStream din = new DataInputStream(sock.getInputStream());
            byte[] msg = receive(din);
            while (!ss.isComplete()) {
                byte[] challenge = ss.evaluateResponse(msg);
                if (ss.isComplete()) {
                    send(dout, challenge, QuorumAuth.Status.SUCCESS);
                    break;
                } else {
                    send(dout, challenge, QuorumAuth.Status.CONTINUE);
                    msg = receive(din);
                }
            }
        } catch (IOException e) {
            throw new AuthException("", e);
        } catch (LoginException e) {
            throw new AuthException("", e);
        } catch (PrivilegedActionException e) {
            throw new AuthException("", e);
        } catch (GSSException e) {
            throw new AuthException("", e);
        } finally {
            if (ss != null) {
                try {
                    ss.dispose();
                } catch (SaslException e) {
                    LOG.error("SaslServer dispose() failed", e);
                }
            }
        }
    }

    private byte[] receive(DataInputStream din) throws IOException {
        // TODO: custom encoding should be replaced by 3rd party messaging format (jute, protobuf).
        int len = din.readInt();
        byte[] b = new byte[len];
        din.readFully(b);
        return b;
    }

    private void send(DataOutputStream dout, byte[] challenge, QuorumAuth.Status s) throws IOException {
        // TODO: custom encoding should be replaced by 3rd party messaging format (jute, protobuf).
        if (challenge != null && challenge.length < 0) {
            throw new IOException("Response length < 0");
        }
        dout.writeInt(s.ordinal());
        if (challenge == null) {
            dout.writeInt(0);
            return;
        }
        dout.writeInt(challenge.length);
        dout.write(challenge);
        dout.flush();
    }

    private SaslServer createSaslServer(final Login login) throws PrivilegedActionException, SaslException, GSSException {
        // This code is copied from ZooKeeperSaslServer.
        Subject subject = login.getSubject();
        // server is using a JAAS-authenticated subject: determine service principal name and hostname from zk server's subject.
        if (subject.getPrincipals().size() > 0) {
            final Object[] principals = subject.getPrincipals().toArray();
            final Principal servicePrincipal = (Principal) principals[0];

            // e.g. servicePrincipalNameAndHostname := "zookeeper/myhost.foo.com@FOO.COM"
            final String servicePrincipalNameAndHostname = servicePrincipal.getName();

            int indexOf = servicePrincipalNameAndHostname.indexOf("/");

            // e.g. servicePrincipalName := "zookeeper"
            final String servicePrincipalName = servicePrincipalNameAndHostname.substring(0, indexOf);

            // e.g. serviceHostnameAndKerbDomain := "myhost.foo.com@FOO.COM"
            final String serviceHostnameAndKerbDomain = servicePrincipalNameAndHostname.substring(indexOf + 1, servicePrincipalNameAndHostname.length());

            indexOf = serviceHostnameAndKerbDomain.indexOf("@");
            // e.g. serviceHostname := "myhost.foo.com"
            final String serviceHostname = serviceHostnameAndKerbDomain.substring(0, indexOf);

            final String mech = "GSSAPI";   // TODO: should depend on zoo.cfg specified mechs, but if subject is non-null, it can be assumed to be GSSAPI.

            LOG.info("serviceHostname is '" + serviceHostname + "'");
            LOG.info("servicePrincipalName is '" + servicePrincipalName + "'");
            LOG.info("SASL mechanism(mech) is '" + mech + "'");

            boolean usingNativeJgss =
                    Boolean.getBoolean("sun.security.jgss.native");
            if (usingNativeJgss) {
                // http://docs.oracle.com/javase/6/docs/technotes/guides/security/jgss/jgss-features.html
                // """
                // In addition, when performing operations as a particular
                // Subject, e.g. Subject.doAs(...) or
                // Subject.doAsPrivileged(...), the to-be-used
                // GSSCredential should be added to Subject's
                // private credential set. Otherwise, the GSS operations
                // will fail since no credential is found.
                // """
                GSSManager manager = GSSManager.getInstance();
                Oid krb5Mechanism = new Oid("1.2.840.113554.1.2.2");
                GSSName gssName = manager.createName(
                        servicePrincipalName + "@" + serviceHostname,
                        GSSName.NT_HOSTBASED_SERVICE);
                GSSCredential cred = manager.createCredential(gssName,
                        GSSContext.DEFAULT_LIFETIME,
                        krb5Mechanism,
                        GSSCredential.ACCEPT_ONLY);
                subject.getPrivateCredentials().add(cred);
            }
            return Subject.doAs(subject, new PrivilegedExceptionAction<SaslServer>() {
                        public SaslServer run() {
                            try {
                                SaslServer saslServer;
                                saslServer = Sasl.createSaslServer(mech, servicePrincipalName, serviceHostname, null, login.callbackHandler);
                                return saslServer;
                            } catch (SaslException e) {
                                LOG.error("Zookeeper Server failed to create a SaslServer to interact with a client during session initiation: " + e);
                                e.printStackTrace();
                                return null;
                            }
                        }
                    }
            );
        } else {
            // JAAS non-GSSAPI authentication: assuming and supporting only DIGEST-MD5 mechanism for now.
            // TODO: use 'authMech=' value in zoo.cfg.
            SaslServer saslServer = Sasl.createSaslServer("DIGEST-MD5", "zookeeper-quorum", "zk-quorum-sasl-md5", null, login.callbackHandler);
            return saslServer;
        }
    }
}

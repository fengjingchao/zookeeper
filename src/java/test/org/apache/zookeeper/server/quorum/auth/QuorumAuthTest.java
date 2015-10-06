package org.apache.zookeeper.server.quorum.auth;

import org.apache.zookeeper.ZKTestCase;
import org.apache.zookeeper.test.ClientBase;
import org.apache.zookeeper.test.ClientTest;
import org.apache.zookeeper.test.QuorumBase;
import org.apache.zookeeper.test.QuorumBaseException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class QuorumAuthTest extends ZKTestCase {
    private static final Logger LOG = LoggerFactory.getLogger(QuorumAuthTest.class);
    static {
        try {
            File tmpDir = ClientBase.createTmpDir();
            File saslConfFile = new File(tmpDir, "jaas.conf");
            FileWriter fwriter = new FileWriter(saslConfFile);

            fwriter.write("" +
                    "QuorumServer {\n" +
                    "       org.apache.zookeeper.server.auth.DigestLoginModule required\n" +
                    "       user_test=\"test\";\n" +
                    "};\n" +
                    "QuorumClient {\n" +
                    "       org.apache.zookeeper.server.auth.DigestLoginModule required\n" +
                    "       username=\"test\"\n" +
                    "       password=\"test\";\n" +
                    "};\n" +
                    "QuorumClient2 {\n" +
                    "       org.apache.zookeeper.server.auth.DigestLoginModule required\n" +
                    "       username=\"test\"\n" +
                    "       password=\"invalid\";\n" +
                    "};" + "\n");
            fwriter.close();
            System.setProperty("java.security.auth.login.config", saslConfFile.getAbsolutePath());
        } catch (IOException e) {
            // could not create tmp directory to hold JAAS conf file : test will fail now.
        }
    }


    @Before
    public void setUp() throws Exception {
        System.setProperty("zookeeper.quorum.auth", "true");
    }

    @After
    public void tearDown() throws Exception {
        System.clearProperty("zookeeper.quorum.auth");
    }

    @Test
    public void testValidCreds() throws Exception {
        QuorumBase qb = new QuorumBase();
        ClientTest ct = new ClientTest();
        qb.setUp();
        ct.setHostPort(qb.getHostPort());
        ct.setUpAll();
        ct.testPing();
        ct.tearDownAll();
        qb.tearDown();
    }

    @Test
    public void testInvalidCreds() throws Exception {
        System.setProperty("zookeeper.quorum.client.loginContext", "QuorumClient2");
        try {
            QuorumBase qb = new QuorumBase(true);
            qb.setUp();
            qb.tearDown();
        } catch (Exception e) {
            if (e instanceof QuorumBaseException) {
                return;
            }
            throw e;
        } finally {
            System.clearProperty("zookeeper.quorum.client.loginContext");
        }
    }
}
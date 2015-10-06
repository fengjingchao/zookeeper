# ZK Quorum Auth Tutorial

I will go through how to setup Quorum Auth by using DIGEST-md5.
The workflow could also be applied to using Kerberos.

## Setting
Create a `jaas.conf` file,
```
QuorumServer {
    org.apache.zookeeper.server.auth.DigestLoginModule required
    user_test="test";
};
QuorumClient {
    org.apache.zookeeper.server.auth.DigestLoginModule required
    username="test"
    password="test";
};
```
Servers will talk to each other using the above credentials.
They are acting like client-server when creating connnections.

Set JVMFLAGS to use `jaas.conf`
```
java.security.auth.login.config=$JAASCONF_DIR/jaas.conf
```
Change `$JAASCONF_DIR` to the directory where `jaas.conf` is.

Set JVMFLAGS to enable quorum auth
```
zookeeper.quorum.auth=true
```

(Optional) If you want to use different logic context for client/server,
set JVM flags:
```
zookeeper.quorum.client.loginContext=".. Client Login Context .."
zookeeper.quorum.server.loginContext=".. Server Login Context .."
```

(Optional) For using Kerberos, also recommends setting JVM flags:
```
javax.security.auth.useSubjectCredsOnly=false
```

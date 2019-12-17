/*
 * Copyright 2019 yomo
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.yomo.maria.binlog;

import com.github.yomo.maria.binlog.event.Event;
import com.github.yomo.maria.binlog.event.EventHeader;
import com.github.yomo.maria.binlog.event.EventHeaderV4;
import com.github.yomo.maria.binlog.event.EventType;
import com.github.yomo.maria.binlog.event.QueryEventData;
import com.github.yomo.maria.binlog.event.RotateEventData;
import com.github.yomo.maria.binlog.event.deserialization.ChecksumType;
import com.github.yomo.maria.binlog.event.deserialization.EventDataDeserializationException;
import com.github.yomo.maria.binlog.event.deserialization.EventDataDeserializer;
import com.github.yomo.maria.binlog.event.deserialization.EventDeserializer;
import com.github.yomo.maria.binlog.event.deserialization.EventDeserializer.EventDataWrapper;
import com.github.yomo.maria.binlog.event.deserialization.QueryEventDataDeserializer;
import com.github.yomo.maria.binlog.event.deserialization.RotateEventDataDeserializer;
import com.github.yomo.maria.binlog.io.ByteArrayInputStream;
import com.github.yomo.maria.binlog.jmx.BinaryLogClientMXBean;
import com.github.yomo.maria.binlog.network.AuthenticationException;
import com.github.yomo.maria.binlog.network.ClientCapabilities;
import com.github.yomo.maria.binlog.network.DefaultSSLSocketFactory;
import com.github.yomo.maria.binlog.network.SSLMode;
import com.github.yomo.maria.binlog.network.SSLSocketFactory;
import com.github.yomo.maria.binlog.network.ServerException;
import com.github.yomo.maria.binlog.network.SocketFactory;
import com.github.yomo.maria.binlog.network.TLSHostnameVerifier;
import com.github.yomo.maria.binlog.network.protocol.ErrorPacket;
import com.github.yomo.maria.binlog.network.protocol.GreetingPacket;
import com.github.yomo.maria.binlog.network.protocol.Packet;
import com.github.yomo.maria.binlog.network.protocol.PacketChannel;
import com.github.yomo.maria.binlog.network.protocol.ResultSetRowPacket;
import com.github.yomo.maria.binlog.network.protocol.command.AuthenticateCommand;
import com.github.yomo.maria.binlog.network.protocol.command.AuthenticateNativePasswordCommand;
import com.github.yomo.maria.binlog.network.protocol.command.Command;
import com.github.yomo.maria.binlog.network.protocol.command.DumpBinaryLogCommand;
import com.github.yomo.maria.binlog.network.protocol.command.PingCommand;
import com.github.yomo.maria.binlog.network.protocol.command.QueryCommand;
import com.github.yomo.maria.binlog.network.protocol.command.SSLRequestCommand;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.yomo.maria.binlog.event.maria.Gtid;
import com.github.yomo.maria.binlog.event.maria.MariaGtidEventData;
import com.github.yomo.maria.binlog.network.protocol.command.RegisterSlaveCommand;
import com.github.yomo.maria.binlog.event.deserialization.maria.GtidDeserializer;
import com.github.yomo.maria.binlog.event.deserialization.maria.BinlogCheckpointDeserializer;
import com.github.yomo.maria.binlog.event.deserialization.maria.GtidListDeserializer;

/**
 * MySQL replication stream client.
 *
 */
public class BinaryLogClient implements BinaryLogClientMXBean {

    private static final SSLSocketFactory DEFAULT_REQUIRED_SSL_MODE_SOCKET_FACTORY = new DefaultSSLSocketFactory() {

        @Override
        protected void initSSLContext(SSLContext sc) throws GeneralSecurityException {
            sc.init(null, new TrustManager[]{
                new X509TrustManager() {

                    @Override
                    public void checkClientTrusted(X509Certificate[] x509Certificates, String s)
                        throws CertificateException { }

                    @Override
                    public void checkServerTrusted(X509Certificate[] x509Certificates, String s)
                        throws CertificateException { }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
            }, null);
        }
    };
    private static final SSLSocketFactory DEFAULT_VERIFY_CA_SSL_MODE_SOCKET_FACTORY = new DefaultSSLSocketFactory();

    // https://dev.mysql.com/doc/internals/en/sending-more-than-16mbyte.html
    private static final int MAX_PACKET_LENGTH = 16777215;
    private final Logger logger = LoggerFactory.getLogger(getClass().getName());

    private final String hostname;
    private final int port;
    private final String schema;
    private final String username;
    private final String password;

    private boolean blocking = true;
    private long serverId = 65535;
    private volatile String binlogFilename;
    private volatile long binlogPosition = 4;
    private volatile long connectionId;
    private SSLMode sslMode = SSLMode.DISABLED;

    private final Object gtidAccessLock = new Object();
    private String gtid;
    private String commitGtid;
    private Map<Integer, String> gtidList = new LinkedHashMap<Integer, String>();

    private boolean tx;

    private EventDeserializer eventDeserializer = new EventDeserializer();

    private final List<EventListener> eventListeners = new CopyOnWriteArrayList<EventListener>();
    private final List<LifecycleListener> lifecycleListeners = new CopyOnWriteArrayList<LifecycleListener>();

    private SocketFactory socketFactory;
    private SSLSocketFactory sslSocketFactory;

    private volatile PacketChannel channel;
    private volatile boolean connected;

    private ThreadFactory threadFactory;

    private boolean keepAlive = true;
    private long keepAliveInterval = TimeUnit.MINUTES.toMillis(1);

    private long heartbeatInterval;
    private volatile long eventLastSeen;

    private long connectTimeout = TimeUnit.SECONDS.toMillis(3);

    private volatile ExecutorService keepAliveThreadExecutor;

    private final Lock connectLock = new ReentrantLock();
    private final Lock keepAliveThreadExecutorLock = new ReentrantLock();

    // Mariadb
    private Gtid mariaGtid;
    private boolean isMariaDB;

    /**
     * Alias for BinaryLogClient("localhost", 3306, &lt;no schema&gt; = null, username, password).
     * @see BinaryLogClient#BinaryLogClient(String, int, String, String, String)
     */
    public BinaryLogClient(String username, String password) {
        this("localhost", 3306, null, username, password);
    }

    /**
     * Alias for BinaryLogClient("localhost", 3306, schema, username, password).
     * @see BinaryLogClient#BinaryLogClient(String, int, String, String, String)
     */
    public BinaryLogClient(String schema, String username, String password) {
        this("localhost", 3306, schema, username, password);
    }

    /**
     * Alias for BinaryLogClient(hostname, port, &lt;no schema&gt; = null, username, password).
     * @see BinaryLogClient#BinaryLogClient(String, int, String, String, String)
     */
    public BinaryLogClient(String hostname, int port, String username, String password) {
        this(hostname, port, null, username, password);
    }

    /**
     * @param hostname mysql server hostname
     * @param port mysql server port
     * @param schema database name, nullable. Note that this parameter has nothing to do with event filtering. It's
     * used only during the authentication.
     * @param username login name
     * @param password password
     */
    public BinaryLogClient(String hostname, int port, String schema, String username, String password) {
        this.hostname = hostname;
        this.port = port;
        this.schema = schema;
        this.username = username;
        this.password = password;
    }

    public boolean isBlocking() {
        return blocking;
    }

    /**
     * @param blocking blocking mode. If set to false - BinaryLogClient will disconnect after the last event.
     */
    public void setBlocking(boolean blocking) {
        this.blocking = blocking;
    }

    public SSLMode getSSLMode() {
        return sslMode;
    }

    public void setSSLMode(SSLMode sslMode) {
        if (sslMode == null) {
            throw new IllegalArgumentException("SSL mode cannot be NULL");
        }
        this.sslMode = sslMode;
    }

    /**
     * @return server id (65535 by default)
     * @see #setServerId(long)
     */
    public long getServerId() {
        return serverId;
    }

    /**
     * @param serverId server id (in the range from 1 to 2^32 - 1). This value MUST be unique across whole replication
     * group (that is, different from any other server id being used by any master or slave). Keep in mind that each
     * binary log client (mysql-binlog-connector-java/BinaryLogClient, mysqlbinlog, etc) should be treated as a
     * simplified slave and thus MUST also use a different server id.
     * @see #getServerId()
     */
    public void setServerId(long serverId) {
        this.serverId = serverId;
    }

    /**
     * @return binary log filename, nullable (and null be default). Note that this value is automatically tracked by
     * the client and thus is subject to change (in response to {@link EventType#ROTATE}, for example).
     * @see #setBinlogFilename(String)
     */
    public String getBinlogFilename() {
        return binlogFilename;
    }

    /**
     * @param binlogFilename binary log filename.
     * Special values are:
     * <ul>
     *   <li>null, which turns on automatic resolution (resulting in the last known binlog and position). This is what
     * happens by default when you don't specify binary log filename explicitly.</li>
     *   <li>"" (empty string), which instructs server to stream events starting from the oldest known binlog.</li>
     * </ul>
     * @see #getBinlogFilename()
     */
    public void setBinlogFilename(String binlogFilename) {
        this.binlogFilename = binlogFilename;
    }

    /**
     * @return binary log position of the next event, 4 by default (which is a position of first event). Note that this
     * value changes with each incoming event.
     * @see #setBinlogPosition(long)
     */
    public long getBinlogPosition() {
        return binlogPosition;
    }

    /**
     * @param binlogPosition binary log position. Any value less than 4 gets automatically adjusted to 4 on connect.
     * @see #getBinlogPosition()
     */
    public void setBinlogPosition(long binlogPosition) {
        this.binlogPosition = binlogPosition;
    }

    /**
     * @return thread id
     */
    public long getConnectionId() {
        return connectionId;
    }

    /**
     * @return true if "keep alive" thread should be automatically started (default), false otherwise.
     * @see #setKeepAlive(boolean)
     */
    public boolean isKeepAlive() {
        return keepAlive;
    }

    /**
     * @param keepAlive true if "keep alive" thread should be automatically started (recommended and true by default),
     * false otherwise.
     * @see #isKeepAlive()
     * @see #setKeepAliveInterval(long)
     */
    public void setKeepAlive(boolean keepAlive) {
        this.keepAlive = keepAlive;
    }

    /**
     * @return "keep alive" interval in milliseconds, 1 minute by default.
     * @see #setKeepAliveInterval(long)
     */
    public long getKeepAliveInterval() {
        return keepAliveInterval;
    }

    /**
     * @param keepAliveInterval "keep alive" interval in milliseconds.
     * @see #getKeepAliveInterval()
     * @see #setHeartbeatInterval(long)
     */
    public void setKeepAliveInterval(long keepAliveInterval) {
        this.keepAliveInterval = keepAliveInterval;
    }

    /**
     * @return "keep alive" connect timeout in milliseconds.
     * @see #setKeepAliveConnectTimeout(long)
     *
     * @deprecated in favour of {@link #getConnectTimeout()}
     */
    public long getKeepAliveConnectTimeout() {
        return connectTimeout;
    }

    /**
     * @param connectTimeout "keep alive" connect timeout in milliseconds.
     * @see #getKeepAliveConnectTimeout()
    *
     * @deprecated in favour of {@link #setConnectTimeout(long)}
     */
    public void setKeepAliveConnectTimeout(long connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    /**
     * @return heartbeat period in milliseconds (0 if not set (default)).
     * @see #setHeartbeatInterval(long)
     */
    public long getHeartbeatInterval() {
        return heartbeatInterval;
    }

    /**
     * @param heartbeatInterval heartbeat period in milliseconds.
     * <p>
     * If set (recommended)
     * <ul>
     * <li> HEARTBEAT event will be emitted every "heartbeatInterval".
     * <li> if {@link #setKeepAlive(boolean)} is on then keepAlive thread will attempt to reconnect if no
     *   HEARTBEAT events were received within {@link #setKeepAliveInterval(long)} (instead of trying to send
     *   PING every {@link #setKeepAliveInterval(long)}, which is fundamentally flawed -
     *   https://github.com/shyiko/mysql-binlog-connector-java/issues/118).
     * </ul>
     * Note that when used together with keepAlive heartbeatInterval MUST be set less than keepAliveInterval.
     *
     * @see #getHeartbeatInterval()
     */
    public void setHeartbeatInterval(long heartbeatInterval) {
        this.heartbeatInterval = heartbeatInterval;
    }

    /**
     * @return connect timeout in milliseconds, 3 seconds by default.
     * @see #setConnectTimeout(long)
     */
    public long getConnectTimeout() {
        return connectTimeout;
    }

    /**
     * @param connectTimeout connect timeout in milliseconds.
     * @see #getConnectTimeout()
     */
    public void setConnectTimeout(long connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    /**
     * @param eventDeserializer custom event deserializer
     */
    public void setEventDeserializer(EventDeserializer eventDeserializer) {
        if (eventDeserializer == null) {
            throw new IllegalArgumentException("Event deserializer cannot be NULL");
        }
        this.eventDeserializer = eventDeserializer;
    }

    /**
     * @param socketFactory custom socket factory. If not provided, socket will be created with "new Socket()".
     */
    public void setSocketFactory(SocketFactory socketFactory) {
        this.socketFactory = socketFactory;
    }

    /**
     * @param sslSocketFactory custom ssl socket factory
     */
    public void setSslSocketFactory(SSLSocketFactory sslSocketFactory) {
        this.sslSocketFactory = sslSocketFactory;
    }

    /**
     * @param threadFactory custom thread factory. If not provided, threads will be created using simple "new Thread()".
     */
    public void setThreadFactory(ThreadFactory threadFactory) {
        this.threadFactory = threadFactory;
    }

    /**
     * Connect to the replication stream. Note that this method blocks until disconnected.
     * @throws AuthenticationException if authentication fails
     * @throws ServerException if MySQL server responds with an error
     * @throws IOException if anything goes wrong while trying to connect
     */
    public void connect() throws IOException {
        if (!connectLock.tryLock()) {
            throw new IllegalStateException("BinaryLogClient is already connected");
        }
        boolean notifyWhenDisconnected = false;
        try {
            Callable cancelDisconnect = null;
            try {
                try {
                    long start = System.currentTimeMillis();
                    channel = openChannel();
                    if (connectTimeout > 0 && !isKeepAliveThreadRunning()) {
                        cancelDisconnect = scheduleDisconnectIn(connectTimeout -
                            (System.currentTimeMillis() - start));
                    }
                    if (channel.getInputStream().peek() == -1) {
                        throw new EOFException();
                    }
                } catch (IOException e) {
                    throw new IOException("Failed to connect to MySQL on " + hostname + ":" + port +
                        ". Please make sure it's running.", e);
                }
                GreetingPacket greetingPacket = receiveGreeting();
                authenticate(greetingPacket);
                connectionId = greetingPacket.getThreadId();

                if (binlogFilename == null) {
                    fetchBinlogFilenameAndPosition();
                }
                if (binlogPosition < 4) {
                    logger.warn("Binary log position adjusted from " + binlogPosition + " to " + 4);
                    binlogPosition = 4;
                }
                ChecksumType checksumType = fetchBinlogChecksum();
                if (checksumType != ChecksumType.NONE) {
                    confirmSupportOfChecksum(checksumType);
                }
                if (isMariaDB() || greetingPacket.getServerVersion().contains("MariaDB")) {
                    isMariaDB = true;
                    logger.info("Switch to mariadb mode,server version is " + greetingPacket.getServerVersion());
                }
                if (heartbeatInterval > 0) {
                    enableHeartbeat();
                }
                tx = false;
                requestBinaryLogStream();
            } catch (IOException e) {
                disconnectChannel();
                throw e;
            } finally {
                if (cancelDisconnect != null) {
                    try {
                        cancelDisconnect.call();
                    } catch (Exception e) {
                        logger.warn("\"" + e.getMessage() +
                            "\" was thrown while canceling scheduled disconnect call");
                    }
                }
            }
            connected = true;
            notifyWhenDisconnected = true;
            String position;
            synchronized (gtidAccessLock) {
                position = gtid != null ? gtid : binlogFilename + "/" + binlogPosition;
            }
            logger.info("Connected to " + hostname + ":" + port + " at " + position +
                " (" + (blocking ? "sid:" + serverId + ", " : "") + "cid:" + connectionId + ")");
            for (LifecycleListener lifecycleListener : lifecycleListeners) {
                lifecycleListener.onConnect(this);
            }
            if (keepAlive && !isKeepAliveThreadRunning()) {
                spawnKeepAliveThread();
            }
            ensureEventDataDeserializer(EventType.ROTATE, RotateEventDataDeserializer.class);
            synchronized (gtidAccessLock) {
                if (gtid != null) {
                    //ensureEventDataDeserializer(EventType.GTID, GtidEventDataDeserializer.class);
                    ensureEventDataDeserializer(EventType.QUERY, QueryEventDataDeserializer.class);
                }
            }
            listenForEventPackets();
        } finally {
            connectLock.unlock();
            if (notifyWhenDisconnected) {
                for (LifecycleListener lifecycleListener : lifecycleListeners) {
                    lifecycleListener.onDisconnect(this);
                }
            }
        }
    }

    private PacketChannel openChannel() throws IOException {
        Socket socket = socketFactory != null ? socketFactory.createSocket() : new Socket();
        socket.connect(new InetSocketAddress(hostname, port), (int) connectTimeout);
        return new PacketChannel(socket);
    }

    private Callable scheduleDisconnectIn(final long timeout) {
        final BinaryLogClient self = this;
        final CountDownLatch connectLatch = new CountDownLatch(1);
        final Thread thread = newNamedThread(new Runnable() {
            @Override
            public void run() {
                try {
                    connectLatch.await(timeout, TimeUnit.MILLISECONDS);
                } catch (InterruptedException e) {
                    logger.warn(e.getMessage());
                }
                if (connectLatch.getCount() != 0) {
                    logger.warn("Failed to establish connection in " + timeout + "ms. " +
                        "Forcing disconnect.");
                    try {
                        self.disconnectChannel();
                    } catch (IOException e) {
                        logger.warn(e.getMessage());
                    }
                }
            }
        }, "blc-disconnect-" + hostname + ":" + port);
        thread.start();
        return new Callable() {

            public Object call() throws Exception {
                connectLatch.countDown();
                thread.join();
                return null;
            }
        };
    }

    private GreetingPacket receiveGreeting() throws IOException {
        byte[] initialHandshakePacket = channel.read();
        if (initialHandshakePacket[0] == (byte) 0xFF /* error */) {
            byte[] bytes = Arrays.copyOfRange(initialHandshakePacket, 1, initialHandshakePacket.length);
            ErrorPacket errorPacket = new ErrorPacket(bytes);
            throw new ServerException(errorPacket.getErrorMessage(), errorPacket.getErrorCode(),
                    errorPacket.getSqlState());
        }
        return new GreetingPacket(initialHandshakePacket);
    }

    private void enableHeartbeat() throws IOException {
        channel.write(new QueryCommand("set @master_heartbeat_period=" + heartbeatInterval * 1000000));
        byte[] statementResult = channel.read();
        if (statementResult[0] == (byte) 0xFF /* error */) {
            byte[] bytes = Arrays.copyOfRange(statementResult, 1, statementResult.length);
            ErrorPacket errorPacket = new ErrorPacket(bytes);
            throw new ServerException(errorPacket.getErrorMessage(), errorPacket.getErrorCode(),
                errorPacket.getSqlState());
        }
    }

    private void requestBinaryLogStream() throws IOException {
        long serverId = blocking ? this.serverId : 0; // http://bugs.mysql.com/bug.php?id=71178
        Command dumpBinaryLogCommand;
        synchronized (gtidAccessLock) {
            dumpBinaryLogCommand = requestMariaBinaryLogStream();
        }
        channel.write(dumpBinaryLogCommand);
    }

    private void ensureEventDataDeserializer(EventType eventType,
             Class<? extends EventDataDeserializer> eventDataDeserializerClass) {
        EventDataDeserializer eventDataDeserializer = eventDeserializer.getEventDataDeserializer(eventType);
        if (eventDataDeserializer.getClass() != eventDataDeserializerClass &&
            eventDataDeserializer.getClass() != EventDataWrapper.Deserializer.class) {
            EventDataDeserializer internalEventDataDeserializer;
            try {
                internalEventDataDeserializer = eventDataDeserializerClass.newInstance();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            eventDeserializer.setEventDataDeserializer(eventType,
                new EventDataWrapper.Deserializer(internalEventDataDeserializer,
                    eventDataDeserializer));
        }
    }

    private void authenticate(GreetingPacket greetingPacket) throws IOException {
        int collation = greetingPacket.getServerCollation();
        int packetNumber = 1;

        boolean usingSSLSocket = false;
        if (sslMode != SSLMode.DISABLED) {
            boolean serverSupportsSSL = (greetingPacket.getServerCapabilities() & ClientCapabilities.SSL) != 0;
            if (!serverSupportsSSL && (sslMode == SSLMode.REQUIRED || sslMode == SSLMode.VERIFY_CA ||
                sslMode == SSLMode.VERIFY_IDENTITY)) {
                throw new IOException("MySQL server does not support SSL");
            }
            if (serverSupportsSSL) {
                SSLRequestCommand sslRequestCommand = new SSLRequestCommand();
                sslRequestCommand.setCollation(collation);
                channel.write(sslRequestCommand, packetNumber++);
                SSLSocketFactory sslSocketFactory =
                    this.sslSocketFactory != null ?
                        this.sslSocketFactory :
                        sslMode == SSLMode.REQUIRED || sslMode == SSLMode.PREFERRED ?
                            DEFAULT_REQUIRED_SSL_MODE_SOCKET_FACTORY :
                            DEFAULT_VERIFY_CA_SSL_MODE_SOCKET_FACTORY;
                channel.upgradeToSSL(sslSocketFactory,
                    sslMode == SSLMode.VERIFY_IDENTITY ? new TLSHostnameVerifier() : null);
                usingSSLSocket = true;
            }
        }
        AuthenticateCommand authenticateCommand = new AuthenticateCommand(schema, username, password,
            greetingPacket.getScramble());
        authenticateCommand.setCollation(collation);
        channel.write(authenticateCommand, packetNumber);
        byte[] authenticationResult = channel.read();
        if (authenticationResult[0] != (byte) 0x00 /* ok */) {
            if (authenticationResult[0] == (byte) 0xFF /* error */) {
                byte[] bytes = Arrays.copyOfRange(authenticationResult, 1, authenticationResult.length);
                ErrorPacket errorPacket = new ErrorPacket(bytes);
                throw new AuthenticationException(errorPacket.getErrorMessage(), errorPacket.getErrorCode(),
                    errorPacket.getSqlState());
            } else if (authenticationResult[0] == (byte) 0xFE) {
                switchAuthentication(authenticationResult, usingSSLSocket);
            } else {
                throw new AuthenticationException("Unexpected authentication result (" + authenticationResult[0] + ")");
            }
        }
    }

    private void switchAuthentication(byte[] authenticationResult, boolean usingSSLSocket) throws IOException {
        /*
            Azure-MySQL likes to tell us to switch authentication methods, even though
            we haven't advertised that we support any.  It uses this for some-odd
            reason to send the real password scramble.
        */
        ByteArrayInputStream buffer = new ByteArrayInputStream(authenticationResult);
        buffer.read(1);

        String authName = buffer.readZeroTerminatedString();
        if ("mysql_native_password".equals(authName)) {
            String scramble = buffer.readZeroTerminatedString();

            Command switchCommand = new AuthenticateNativePasswordCommand(scramble, password);
            channel.write(switchCommand, (usingSSLSocket ? 4 : 3));
            byte[] authResult = channel.read();

            if (authResult[0] != (byte) 0x00) {
                byte[] bytes = Arrays.copyOfRange(authResult, 1, authResult.length);
                ErrorPacket errorPacket = new ErrorPacket(bytes);
                buffer.close();
                throw new AuthenticationException(errorPacket.getErrorMessage(), errorPacket.getErrorCode(),
                    errorPacket.getSqlState());
            }
        } else {
        	buffer.close();
            throw new AuthenticationException("Unsupported authentication type: " + authName);
        }
        buffer.close();
    }

    private void spawnKeepAliveThread() {
        final ExecutorService threadExecutor =
            Executors.newSingleThreadExecutor(new ThreadFactory() {

                @Override
                public Thread newThread(Runnable runnable) {
                    return newNamedThread(runnable, "blc-keepalive-" + hostname + ":" + port);
                }
            });
        try {
            keepAliveThreadExecutorLock.lock();
            threadExecutor.submit(new Runnable() {
                @Override
                public void run() {
                    while (!threadExecutor.isShutdown()) {
                        try {
                            Thread.sleep(keepAliveInterval);
                        } catch (InterruptedException e) {
                            // expected in case of disconnect
                        }
                        if (threadExecutor.isShutdown()) {
                            return;
                        }
                        boolean connectionLost = false;
                        if (heartbeatInterval > 0) {
                            connectionLost = System.currentTimeMillis() - eventLastSeen > keepAliveInterval;
                        } else {
                            try {
                                channel.write(new PingCommand());
                            } catch (IOException e) {
                                connectionLost = true;
                            }
                        }
                        if (connectionLost) {
                            logger.info("Trying to restore lost connection to " + hostname + ":" + port);
                            try {
                                terminateConnect();
                                connect(connectTimeout);
                            } catch (Exception ce) {
                                logger.warn("Failed to restore connection to " + hostname + ":" + port +
                                    ". Next attempt in " + keepAliveInterval + "ms");
                            }
                        }
                    }
                }
            });
            keepAliveThreadExecutor = threadExecutor;
        } finally {
            keepAliveThreadExecutorLock.unlock();
        }
    }

    private Thread newNamedThread(Runnable runnable, String threadName) {
        Thread thread = threadFactory == null ? new Thread(runnable) : threadFactory.newThread(runnable);
        thread.setName(threadName);
        return thread;
    }

    boolean isKeepAliveThreadRunning() {
        try {
            keepAliveThreadExecutorLock.lock();
            return keepAliveThreadExecutor != null && !keepAliveThreadExecutor.isShutdown();
        } finally {
            keepAliveThreadExecutorLock.unlock();
        }
    }

    /**
     * Connect to the replication stream in a separate thread.
     * @param timeout timeout in milliseconds
     * @throws AuthenticationException if authentication fails
     * @throws ServerException if MySQL server responds with an error
     * @throws IOException if anything goes wrong while trying to connect
     * @throws TimeoutException if client was unable to connect within given time limit
     */
    @SuppressWarnings("finally")
	public void connect(final long timeout) throws IOException, TimeoutException {
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        AbstractLifecycleListener connectListener = new AbstractLifecycleListener() {
            @Override
            public void onConnect(BinaryLogClient client) {
                countDownLatch.countDown();
            }
        };
        registerLifecycleListener(connectListener);
        final AtomicReference<IOException> exceptionReference = new AtomicReference<IOException>();
        Runnable runnable = new Runnable() {

            @Override
            public void run() {
                try {
                    setConnectTimeout(timeout);
                    connect();
                } catch (IOException e) {
                    exceptionReference.set(e);
                    countDownLatch.countDown(); // making sure we don't end up waiting whole "timeout"
                }
            }
        };
        newNamedThread(runnable, "blc-" + hostname + ":" + port).start();
        boolean started = false;
        try {
            started = countDownLatch.await(timeout, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            logger.warn( e.getMessage());  
        }
        unregisterLifecycleListener(connectListener);
        if (exceptionReference.get() != null) {
            throw exceptionReference.get();
        }
        if (!started) {
            try {
                terminateConnect();
            } finally {
                throw new TimeoutException("BinaryLogClient was unable to connect in " + timeout + "ms");
            }
        }
    }

    /**
     * @return true if client is connected, false otherwise
     */
    public boolean isConnected() {
        return connected;
    }

    private void fetchBinlogFilenameAndPosition() throws IOException {
        ResultSetRowPacket[] resultSet;
        channel.write(new QueryCommand("show master status"));
        resultSet = readResultSet();
        if (resultSet.length == 0) {
            throw new IOException("Failed to determine binlog filename/position");
        }
        ResultSetRowPacket resultSetRow = resultSet[0];
        binlogFilename = resultSetRow.getValue(0);
        binlogPosition = Long.parseLong(resultSetRow.getValue(1));
    }

    private ChecksumType fetchBinlogChecksum() throws IOException {
        channel.write(new QueryCommand("show global variables like 'binlog_checksum'"));
        ResultSetRowPacket[] resultSet = readResultSet();
        if (resultSet.length == 0) {
            return ChecksumType.NONE;
        }
        return ChecksumType.valueOf(resultSet[0].getValue(1).toUpperCase());
    }

    @SuppressWarnings("deprecation")
	private void confirmSupportOfChecksum(ChecksumType checksumType) throws IOException {
        channel.write(new QueryCommand("set @master_binlog_checksum= @@global.binlog_checksum"));
        byte[] statementResult = channel.read();
        if (statementResult[0] == (byte) 0xFF /* error */) {
            byte[] bytes = Arrays.copyOfRange(statementResult, 1, statementResult.length);
            ErrorPacket errorPacket = new ErrorPacket(bytes);
            throw new ServerException(errorPacket.getErrorMessage(), errorPacket.getErrorCode(),
                errorPacket.getSqlState());
        }
        eventDeserializer.setChecksumType(checksumType);
    }

    private void listenForEventPackets() throws IOException {
        ByteArrayInputStream inputStream = channel.getInputStream();
        
        boolean completeShutdown = false;
        try {
            while (inputStream.peek() != -1) {
                int packetLength = inputStream.readInteger(3);
                inputStream.skip(1); // 1 byte for sequence
                int marker = inputStream.read();
                if (marker == 0xFF) {
                    ErrorPacket errorPacket = new ErrorPacket(inputStream.read(packetLength - 1));
                    throw new ServerException(errorPacket.getErrorMessage(), errorPacket.getErrorCode(),
                        errorPacket.getSqlState());
                }
                if (marker == 0xFE && !blocking) {
                    completeShutdown = true;
                    break;
                }
                Event event;
                try {
                    event = eventDeserializer.nextEvent(packetLength == MAX_PACKET_LENGTH ?
                        new ByteArrayInputStream(readPacketSplitInChunks(inputStream, packetLength - 1)) :
                        inputStream);
                    logger.debug("Received event " + event.toString());
                    if (event == null) {
                        throw new EOFException();
                    }
                } catch (Exception e) {
                    Throwable cause = e instanceof EventDataDeserializationException ? e.getCause() : e;
                    if (cause instanceof EOFException || cause instanceof SocketException) {
                        throw e;
                    }
                    if (isConnected()) {
                        for (LifecycleListener lifecycleListener : lifecycleListeners) {
                            lifecycleListener.onEventDeserializationFailure(this, e);
                        }
                    }
                    continue;
                }
                // If the event.getData() is null and event is not null, now the deserialization is in the recovery mode
                if (isConnected() && event.getData() != null) {
                	logger.debug("replication mode event data: " + event.getData().toString());
                    eventLastSeen = System.currentTimeMillis();
                    updateGtid(event);
                    notifyEventListeners(event);
                    updateClientBinlogFilenameAndPosition(event);
                }
            }
        } catch (Exception e) {
        	logger.warn("listenForEventPackets", e);
            if (isConnected()) {
                for (LifecycleListener lifecycleListener : lifecycleListeners) {
                    lifecycleListener.onCommunicationFailure(this, e);
                }
            }
        } finally {
            if (isConnected()) {
                if (completeShutdown) {
                    disconnect(); // initiate complete shutdown sequence (which includes keep alive thread)
                } else {
                    disconnectChannel();
                }
            }
        }
    }

    private byte[] readPacketSplitInChunks(ByteArrayInputStream inputStream, int packetLength) throws IOException {
    	byte[] result = inputStream.read(packetLength);
        int chunkLength;
        do {
            chunkLength = inputStream.readInteger(3);
            inputStream.skip(1); // 1 byte for sequence
            result = Arrays.copyOf(result, result.length + chunkLength);
            inputStream.fill(result, result.length - chunkLength, chunkLength);
        } while (chunkLength == Packet.MAX_LENGTH);
        return result;
    }

    private void updateClientBinlogFilenameAndPosition(Event event) {
        EventHeader eventHeader = event.getHeader();
        EventType eventType = eventHeader.getEventType();
        if (eventType == EventType.ROTATE) {
            RotateEventData rotateEventData = (RotateEventData) EventDataWrapper.internal(event.getData());
            binlogFilename = rotateEventData.getBinlogFilename();
            binlogPosition = rotateEventData.getBinlogPosition();
        }

        if (eventType == EventType.MARIA_GTID_EVENT){
            //logger.info("Updating the GTID " + event.getHeader().toString());
            updateMariaGTID(event);
        }

        // do not update binlogPosition on TABLE_MAP so that in case of reconnect (using a different instance of
        // client) table mapping cache could be reconstructed before hitting row mutation event
        if (eventType != EventType.TABLE_MAP && eventHeader instanceof EventHeaderV4) {
            EventHeaderV4 trackableEventHeader = (EventHeaderV4) eventHeader;
            long nextBinlogPosition = trackableEventHeader.getNextPosition();
            if (nextBinlogPosition > 0) {
                binlogPosition = nextBinlogPosition;
            }
        }
    }

    private void updateGtid(Event event) {
        synchronized (gtidAccessLock) {
            if (gtid == null) {
                return;
            }
        }
        EventHeader eventHeader = event.getHeader();
        MariaGtidEventData gtidEventData;
        switch(eventHeader.getEventType()) {
            case MARIA_GTID_EVENT:
                gtidEventData = (MariaGtidEventData) EventDataWrapper.internal(event.getData());
                gtid = String.format("%d-%d-%d", gtidEventData.getDomainId(), event.getHeader().getServerId() , gtidEventData.getSequenceNumber());
                tx = true;
                break;
            case XID:
            	commitGtid();
                tx = false;
                break;
            case QUERY:
                QueryEventData queryEventData = (QueryEventData) EventDataWrapper.internal(event.getData());
                String sql = queryEventData.getSql();
                if (sql == null) {
                    break;
                }
                tx = false;
                if(!"ROLLBACK".equals(sql)) {
                	commitGtid(); 
                } 
            default:
        }
    }

    private void commitGtid() {
        if (gtid != null) {
            synchronized (gtidAccessLock) {
                commitGtid = gtid;
                String[] splitGtid = gtid.split("-");
                gtidList.put(Integer.parseInt(splitGtid[0]), gtid);
            }
        }
    }

    private ResultSetRowPacket[] readResultSet() throws IOException {
        List<ResultSetRowPacket> resultSet = new LinkedList<ResultSetRowPacket>();
        byte[] statementResult = channel.read();
        if (statementResult[0] == (byte) 0xFF /* error */) {
            byte[] bytes = Arrays.copyOfRange(statementResult, 1, statementResult.length);
            ErrorPacket errorPacket = new ErrorPacket(bytes);
            throw new ServerException(errorPacket.getErrorMessage(), errorPacket.getErrorCode(),
                    errorPacket.getSqlState());
        }
        while ((channel.read())[0] != (byte) 0xFE /* eof */) { /* skip */ }
        for (byte[] bytes; (bytes = channel.read())[0] != (byte) 0xFE /* eof */; ) {
            resultSet.add(new ResultSetRowPacket(bytes));
        }
        return resultSet.toArray(new ResultSetRowPacket[resultSet.size()]);
    }

    /**
     * @return registered event listeners
     */
    public List<EventListener> getEventListeners() {
        return Collections.unmodifiableList(eventListeners);
    }

    /**
     * Register event listener. Note that multiple event listeners will be called in order they
     * where registered.
     */
    public void registerEventListener(EventListener eventListener) {
        eventListeners.add(eventListener);
    }

    /**
     * Unregister all event listener of specific type.
     */
    public void unregisterEventListener(Class<? extends EventListener> listenerClass) {
        for (EventListener eventListener: eventListeners) {
            if (listenerClass.isInstance(eventListener)) {
                eventListeners.remove(eventListener);
            }
        }
    }

    /**
     * Unregister single event listener.
     */
    public void unregisterEventListener(EventListener eventListener) {
        eventListeners.remove(eventListener);
    }

    private void notifyEventListeners(Event event) {
        if (event.getData() instanceof EventDataWrapper) {
            event = new Event(event.getHeader(), ((EventDataWrapper) event.getData()).getExternal());
        }
        for (EventListener eventListener : eventListeners) {
            try {
                eventListener.onEvent(event);
            } catch (Exception e) {
                logger.warn(eventListener + " choked on " + event, e);
                
            }
        }
    }

    /**
     * @return registered lifecycle listeners
     */
    public List<LifecycleListener> getLifecycleListeners() {
        return Collections.unmodifiableList(lifecycleListeners);
    }

    /**
     * Register lifecycle listener. Note that multiple lifecycle listeners will be called in order they
     * where registered.
     */
    public void registerLifecycleListener(LifecycleListener lifecycleListener) {
        lifecycleListeners.add(lifecycleListener);
    }

    /**
     * Unregister all lifecycle listener of specific type.
     */
    public void unregisterLifecycleListener(Class<? extends LifecycleListener> listenerClass) {
        for (LifecycleListener lifecycleListener : lifecycleListeners) {
            if (listenerClass.isInstance(lifecycleListener)) {
                lifecycleListeners.remove(lifecycleListener);
            }
        }
    }

    /**
     * Unregister single lifecycle listener.
     */
    public void unregisterLifecycleListener(LifecycleListener eventListener) {
        lifecycleListeners.remove(eventListener);
    }

    /**
     * Disconnect from the replication stream.
     * Note that this does not cause binlogFilename/binlogPosition to be cleared out.
     * As the result following {@link #connect()} resumes client from where it left off.
     */
    public void disconnect() throws IOException {
        terminateKeepAliveThread();
        terminateConnect();
    }

    private void terminateKeepAliveThread() {
        try {
            keepAliveThreadExecutorLock.lock();
            ExecutorService keepAliveThreadExecutor = this.keepAliveThreadExecutor;
            if (keepAliveThreadExecutor == null) {
                return;
            }
            keepAliveThreadExecutor.shutdownNow();
            while (!awaitTerminationInterruptibly(keepAliveThreadExecutor,
                Long.MAX_VALUE, TimeUnit.NANOSECONDS)) {
                // ignore
            }
        } finally {
            keepAliveThreadExecutorLock.unlock();
        }
    }

    private static boolean awaitTerminationInterruptibly(ExecutorService executorService, long timeout, TimeUnit unit) {
        try {
            return executorService.awaitTermination(timeout, unit);
        } catch (InterruptedException e) {
            return false;
        }
    }

    private void terminateConnect() throws IOException {
        do {
            disconnectChannel();
        } while (!tryLockInterruptibly(connectLock, 1000, TimeUnit.MILLISECONDS));
        connectLock.unlock();
    }

    private static boolean tryLockInterruptibly(Lock lock, long time, TimeUnit unit) {
        try {
            return lock.tryLock(time, unit);
        } catch (InterruptedException e) {
            return false;
        }
    }

    private void disconnectChannel() throws IOException {
        connected = false;
        if (channel != null && channel.isOpen()) {
            channel.close();
        }
    }

    // mariadb
    public boolean isMariaDB() {
        return isMariaDB;
    }

    /**
     * @return Note that this value changes with each received GTID event (provided client is in GTID mode).
     */
    public String getGtidList() {
        synchronized (gtidAccessLock) {
            //return commitGtid;                
            return String.join(",", new ArrayList<String>(gtidList.values()));
        }
    }

    /**
     * @param gtid For MySQL this is GTID set format, for MariaDB the format is domainId-serverId-sequenceNumber(can be an empty string).
     *             <p>NOTE #1: Any value but null will switch BinaryLogClient into a GTID mode (in which case GTID set will be
     *             updated with each incoming GTID event) as well as set binlogFilename to "" (empty string) (meaning
     *             BinaryLogClient will request events "outside of the set" <u>starting from the oldest known binlog</u>).
     *             <p>NOTE #2: {@link #setBinlogFilename(String)} and {@link #setBinlogPosition(long)} can be used to specify the
     *             exact position from which MySQL server should start streaming events (taking into account GTID set).
     * @see #getGtid()
     */
    public BinaryLogClient setGtidList(String gtid) {
        if (gtid != null && this.binlogFilename == null) {
            this.binlogFilename = "";
        }
        if(gtid != null){
            synchronized (gtidAccessLock) {
                this.gtid = gtid;
                Stream.of(gtid.split(",")).forEach(elem -> {
                    String[] splitGtid = new String(elem).split("-");
                    gtidList.put(Integer.parseInt(splitGtid[0]), elem);
                });            
            }
            logger.info("The gtid was set as " + this.gtid);
        }
        return this;
        
    }
 
    private void updateMariaGTID(Event event) {
        EventHeader eventHeader = event.getHeader();
        if (eventHeader.getEventType() == EventType.MARIA_GTID_EVENT) {
            synchronized (gtidAccessLock) {
                if (mariaGtid != null) {
                    MariaGtidEventData eventData = event.getData();
                    mariaGtid.setDomainId(eventData.getDomainId());
                    mariaGtid.setSequenceNumber(eventData.getSequenceNumber());
                    gtid = mariaGtid.toString();
                }
            }
        }
    }

    private DumpBinaryLogCommand requestMariaBinaryLogStream() throws IOException {
    	logger.info("GTID list before reset " +  getGtidList());
    	List<String> filterGtidList = new ArrayList<String>();
    	if ("gtid_current_pos".equals(gtid) || "".equals(gtid) || gtid == null) {
            channel.write(new QueryCommand("select @@gtid_current_pos"));
            ResultSetRowPacket[] rs = readResultSet();
            gtid = rs[0].getValue(0);
            logger.info("Use server current gtid position from db " + gtid);            
        }else {
        	/*
            | gtid           | current_gtid   | oldest gtid    | request gtid   | Comment           |                         
            |----------------+----------------+----------------+----------------+-------------------|                         
            | 1-223344-100   | 1-223344-200   | 1-223344-50    | 1-223344-200   | Hit the parameter |                         
            | , 1-223345-101 | , 1-223345-201 | , 1-223345-53  | , 1-223345-201 |                   |                         
            |----------------+----------------+----------------+----------------+-------------------|                         
            | 1-223344-100   | 1-223344-200   | 1-223344-50    | 1-223344-100   | Add the missed    |                         
            | , 1-223345-101 | , 1-223345-201 | , 1-223345-53  | , 1-223345-101 | gtid from db      |                         
            |                | , 2-223344-401 | , 2-223344-350 | , 2-223344-401 | to request        |                         
            |----------------+----------------+----------------+----------------+-------------------|                         
            | 1-223344-100   | 1-223344-200   | 1-223344-50    | 1-223344-100   | Ignore the missed |                         
            | , 1-223345-101 | , 1-223345-201 | , 1-223345-53  | , 1-223345-101 | gtid which does   |                         
            |                | , 2-223344-401 | , 2-223344-401 | , 2-223344-401 | not in the binlog |                         
            |----------------+----------------+----------------+----------------+-------------------|                         
            | 1-223344-100   | 1-223344-200   | 1-223344-50    | 1-223344-100   | Sent even though  |                         
            | , 1-223345-101 | , 1-223345-201 | , 1-223345-53  | , 1-223345-101 | it does not exist |                         
            | , 3-223344-801 |                |                | , 3-223344-801 | in the binlog     |                         
            |----------------+----------------+----------------+----------------+-------------------| 
            */
        	
        	// gtid: 1-223344-100,1-223345-101,3-223344-801  => [1-223344-100, 1-223345-101, 3-223344-801]
        	//Stream.of(gtid.split(",")).forEach(elem -> { filterGtidList.add(elem);});
        	Map<String, Integer> lstGtidList = new LinkedHashMap<String, Integer>();
            for(String theGtid : (gtid.split(",")) ) {
            	String[] splitGtid = theGtid.split("-");
            	lstGtidList.put(splitGtid[0] + "-" + splitGtid[1], Integer.parseInt(splitGtid[2]));
            }
        	
        	// dbGtid: 1-223344-200,1-223345-201,2-223344-401
        	channel.write(new QueryCommand("select @@gtid_current_pos"));
            ResultSetRowPacket[] rs = readResultSet();
            String dbGtid = rs[0].getValue(0);
            logger.info("Use server current gtid position "+ dbGtid);
            
            // 1-223344-200,1-223345-201,2-223344-401 => {1-223344 -> 200,
            //                                            1-223345 -> 201,
            //                                            2-223344 -> 401 }
            Map<String, Integer> dbLstGtidList = new LinkedHashMap<String, Integer>();
            for(String theGtid : (dbGtid.split(",")) ) {
            	String[] splitGtid = theGtid.split("-");
            	dbLstGtidList.put(splitGtid[0] + "-" + splitGtid[1], Integer.parseInt(splitGtid[2]));
            }
			
            // Get the eldest GTIDlist from db
         	channel.write(new QueryCommand("show binary logs"));
            ResultSetRowPacket[] rsBinLogs = readResultSet();
            String strbinLogFile = rsBinLogs[0].getValue(0);
            logger.info("Oldest binlog file: " + strbinLogFile);
                     
            channel.write(new QueryCommand("show binlog events  in '" + strbinLogFile + "' limit 2"));
            ResultSetRowPacket[] rsBinEvents = readResultSet();
            //[1-223344-50,1-223345-53,2-223344-350] => 1-223344-50,1-223345-53,2-223344-350
            String earlestGtidList = rsBinEvents[1].getValue(5).replace("[", "").replace("]","");
            logger.info("The earliest gtid list : " + earlestGtidList);
           
            // oldest gtid:
            // 1-223344-50,1-223345-53,2-223344-350 => {1-223344 -> 50 ,
            //                                          1-223345 -> 53 ,
            //                                          2-223344 -> 350 }
            Map<String, Integer> earlestLstGtidList = new LinkedHashMap<String, Integer>();
            for(String theGtid : (earlestGtidList.split(",")) ) {
            	String[] splitGtid = theGtid.split("-");
            	earlestLstGtidList.put(splitGtid[0] + "-" + splitGtid[1], Integer.parseInt(splitGtid[2]));
            }
                     
            // Add the current gtid if it does not exsit in the gtidList
            dbLstGtidList.forEach((key, value) -> {
                //if( earlestLstGtidList.get(key) < value && lstGtidList.get(key) == null) {
            	if(lstGtidList.get(key) == null) {
                	filterGtidList.add(key + "-" + value);
                }else {
                	filterGtidList.add(key + "-" + lstGtidList.get(key));
                }
            });
            gtid = String.join(",", new ArrayList<String>(filterGtidList));
        }
    	
    	String[] split = gtid.split(",");
        for (String s : split) {
        	String[] splitGtid = s.split("-");
            gtidList.put(Integer.parseInt(splitGtid[0]), s);
        }
    	
        logger.info("Gtid list after reset " +  gtid);

        // set up gtid
        channel.write(new QueryCommand("SET @mariadb_slave_capability = 4"));// support GTID
        channel.read();// ignore
        channel.write(new QueryCommand("SET @slave_connect_state = \"" + gtid  + "\""));
        channel.read();// ignore
        channel.write(new QueryCommand("SET @slave_gtid_strict_mode = 0"));
        channel.read();// ignore
        channel.write(new QueryCommand("SET @slave_gtid_ignore_duplicates = 0"));
        channel.read();// ignore
        		
        // Register First
        Command command = new RegisterSlaveCommand(serverId, "", "", "", 0, 0, 0);
        channel.write(command);
        channel.read();// ignore

        // MariaDB Event
        eventDeserializer.setEventDataDeserializer(EventType.MARIA_GTID_EVENT, new GtidDeserializer());
        eventDeserializer.setEventDataDeserializer(EventType.MARIA_GTID_LIST_EVENT, new GtidListDeserializer());
        eventDeserializer.setEventDataDeserializer(EventType.MARIA_BINLOG_CHECKPOINT_EVENT, new BinlogCheckpointDeserializer());
        return new DumpBinaryLogCommand(this.serverId, "", 0);
    }

   // end mariadb

    /**
     * {@link BinaryLogClient}'s event listener.
     */
    public interface EventListener {

        void onEvent(Event event);
    }

    /**
     * {@link BinaryLogClient}'s lifecycle listener.
     */
    public interface LifecycleListener {

        /**
         * Called once client has successfully logged in but before started to receive binlog events.
         */
        void onConnect(BinaryLogClient client);

        /**
         * It's guarantied to be called before {@link #onDisconnect(BinaryLogClient)}) in case of
         * communication failure.
         */
        void onCommunicationFailure(BinaryLogClient client, Exception ex);

        /**
         * Called in case of failed event deserialization. Note this type of error does NOT cause client to
         * disconnect. If you wish to stop receiving events you'll need to fire client.disconnect() manually.
         */
        void onEventDeserializationFailure(BinaryLogClient client, Exception ex);

        /**
         * Called upon disconnect (regardless of the reason).
         */
        void onDisconnect(BinaryLogClient client);
    }

    /**
     * Default (no-op) implementation of {@link LifecycleListener}.
     */
    public static abstract class AbstractLifecycleListener implements LifecycleListener {

        public void onConnect(BinaryLogClient client) { }

        public void onCommunicationFailure(BinaryLogClient client, Exception ex) { }

        public void onEventDeserializationFailure(BinaryLogClient client, Exception ex) { }

        public void onDisconnect(BinaryLogClient client) { }

    }

}

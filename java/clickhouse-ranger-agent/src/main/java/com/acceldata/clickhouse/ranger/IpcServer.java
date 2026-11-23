package com.acceldata.clickhouse.ranger;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Minimal line-based TCP server (localhost only). Each connection may send many requests;
 * every request line gets exactly one response line.
 * The transport is deliberately simple and hidden behind RequestHandler, so it can be swapped
 * (Unix socket, protobuf, ...) without touching the authorization logic.
 */
public final class IpcServer implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(IpcServer.class.getName());
    static final int MAX_LINE_BYTES = 64 * 1024;

    private final RequestHandler handler;
    private final String host;
    private final int port;
    private final int idleTimeoutMs;
    private final ExecutorService workers;
    private volatile ServerSocket serverSocket;
    private volatile boolean running;

    public IpcServer(RequestHandler handler, String host, int port, int maxConnections, int idleTimeoutMs) {
        this.handler = handler;
        this.host = host;
        this.port = port;
        this.idleTimeoutMs = idleTimeoutMs;
        AtomicInteger n = new AtomicInteger();
        this.workers = Executors.newFixedThreadPool(maxConnections, r -> {
            Thread t = new Thread(r, "ipc-worker-" + n.incrementAndGet());
            t.setDaemon(true);
            return t;
        });
    }

    public void start() throws IOException {
        ServerSocket ss = new ServerSocket();
        ss.setReuseAddress(true);
        ss.bind(new InetSocketAddress(InetAddress.getByName(host), port));
        this.serverSocket = ss;
        this.running = true;
        Thread acceptor = new Thread(this::acceptLoop, "ipc-acceptor");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    /** Actual bound port (useful when started with port 0 in tests). */
    public int getPort() {
        return serverSocket.getLocalPort();
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket s = serverSocket.accept();
                try {
                    workers.execute(() -> serve(s));
                } catch (RuntimeException rejected) {
                    closeQuietly(s);
                }
            } catch (IOException e) {
                if (running) LOG.log(Level.WARNING, "accept failed", e);
            }
        }
    }

    private void serve(Socket s) {
        try (Socket sock = s;
             InputStream in = new BufferedInputStream(sock.getInputStream());
             OutputStream out = new BufferedOutputStream(sock.getOutputStream())) {
            sock.setSoTimeout(idleTimeoutMs);
            sock.setTcpNoDelay(true);
            String line;
            while ((line = readLine(in)) != null) {
                String response = handler.handle(line);
                out.write((response + "\n").getBytes(StandardCharsets.UTF_8));
                out.flush();
            }
        } catch (IOException e) {
            // idle timeout, oversize line or client gone: just drop the connection
            LOG.fine("connection closed: " + e);
        }
    }

    /** Reads one '\n'-terminated line, bounded to MAX_LINE_BYTES. Returns null on EOF. */
    static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(128);
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                byte[] bytes = buf.toByteArray();
                int len = bytes.length;
                if (len > 0 && bytes[len - 1] == '\r') len--;
                return new String(bytes, 0, len, StandardCharsets.UTF_8);
            }
            if (buf.size() >= MAX_LINE_BYTES) throw new IOException("line too long");
            buf.write(b);
        }
        return buf.size() == 0 ? null : buf.toString(StandardCharsets.UTF_8);
    }

    private static void closeQuietly(Socket s) {
        try { s.close(); } catch (IOException ignored) { }
    }

    @Override
    public void close() {
        running = false;
        try { if (serverSocket != null) serverSocket.close(); } catch (IOException ignored) { }
        workers.shutdownNow();
        try { workers.awaitTermination(2, TimeUnit.SECONDS); } catch (InterruptedException ignored) { }
    }
}

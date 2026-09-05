package com.company.remoteaccess.client;

import com.company.remoteaccess.core.configuration.AppConfig;
import com.company.remoteaccess.core.state.ConnectionState;
import com.company.remoteaccess.logging.AppLogger;
import com.company.remoteaccess.logging.LogCategory;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Optional automatic client reconnect (spec section 15).
 *
 * <p>Reconnects with exponential backoff, never faster than a minimum interval,
 * and gives up after a bounded number of attempts per session. Credentials /
 * authorization failures and permission problems are never auto-retried.
 */
public final class ReconnectManager implements AutoCloseable {

    static final ConnectionState[] AUTO_RETRYABLE = {
            ConnectionState.SERVER_UNAVAILABLE,
            ConnectionState.NETWORK_UNAVAILABLE,
            ConnectionState.VPN_FAILED,
            ConnectionState.ERROR,
            ConnectionState.RETRYING
    };

    private final ClientService client;
    private final Supplier<AppConfig> config;
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "client-reconnect");
        t.setDaemon(true);
        return t;
    });

    private volatile ScheduledFuture<?> pending;
    private volatile int attemptsThisSession;
    private volatile boolean userWantsConnected;

    public ReconnectManager(ClientService client, Supplier<AppConfig> config) {
        this.client = client;
        this.config = config;
    }

    public void start() {
        client.state.addListener((from, to) -> onState(to));
    }

    private void onState(ConnectionState to) {
        if (to == ConnectionState.CONNECTED) {
            attemptsThisSession = 0;
        }
        AppConfig cfg = config.get();
        boolean auto = cfg != null && cfg.autoReconnect();
        if (auto && retryable(to)) {
            scheduleRetry();
        }
    }

    private boolean retryable(ConnectionState to) {
        for (ConnectionState c : AUTO_RETRYABLE) {
            if (c == to) {
                return true;
            }
        }
        return false;
    }

    private void scheduleRetry() {
        synchronized (scheduler) {
            if (pending != null && !pending.isDone()) {
                return;
            }
            if (attemptsThisSession >= maxAttempts()) {
                AppLogger.getLogger().warn(LogCategory.CLIENT,
                        "auto-reconnect gave up after %d attempts", attemptsThisSession);
                return;
            }
            long delay = backoff(attemptsThisSession);
            attemptsThisSession++;
            AppLogger.getLogger().info(LogCategory.CLIENT,
                    "auto-reconnect scheduled in %d ms (attempt %d)", delay, attemptsThisSession);
            pending = scheduler.schedule(() -> {
                try {
                    client.state.transitionTo(ConnectionState.RETRYING);
                } catch (IllegalStateException ignored) {
                }
                client.connect();
            }, delay, TimeUnit.MILLISECONDS);
        }
    }

    /** @param manual true when the user pressed CONNECT (restarts the retry budget). */
    public void onUserRequestedConnect() {
        attemptsThisSession = 0;
        cancelPending();
        // the connect itself will drive the state
    }

    public void onUserRequestedDisconnect() {
        cancelPending();
        attemptsThisSession = 0;
    }

    public void cancelPending() {
        ScheduledFuture<?> f = pending;
        if (f != null && !f.isDone()) {
            f.cancel(false);
        }
        pending = null;
    }

    private int maxAttempts() {
        AppConfig cfg = config.get();
        return cfg == null || cfg.maxRetries() <= 0 ? 5 : Math.min(cfg.maxRetries() * 2, 20);
    }

    /** Backoff grows from base toward 60 s. */
    private long backoff(int attempt) {
        AppConfig cfg = config.get();
        long base = cfg == null || cfg.backoffBaseMs() <= 0 ? 2000 : cfg.backoffBaseMs();
        long capped = Math.min(base << Math.min(attempt, 5), 60_000);
        long jitter = (long) (Math.random() * 250);
        return capped + jitter;
    }

    @Override
    public void close() {
        cancelPending();
        scheduler.shutdownNow();
    }
}
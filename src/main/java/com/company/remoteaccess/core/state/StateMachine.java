package com.company.remoteaccess.core.state;

import com.company.remoteaccess.logging.AppLogger;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe connection state machine with an explicit transition table.
 *
 * <p>Listeners are invoked synchronously on the notifier thread; the UI wraps
 * notifications in {@link javafx.application.Platform#runLater}.
 */
public final class StateMachine {

    public interface Listener {
        /** @param from the previous state (nullable on first registration) */
        void onStateChanged(ConnectionState from, ConnectionState to);
    }

    private static final Set<ConnectionState> FAILURE_STATES = EnumSet.of(
            ConnectionState.ERROR,
            ConnectionState.AUTH_FAILED,
            ConnectionState.SERVER_UNAVAILABLE,
            ConnectionState.NETWORK_UNAVAILABLE,
            ConnectionState.PERMISSION_REQUIRED,
            ConnectionState.VPN_FAILED);

    private static final Set<ConnectionState> DRIVING_STATES = EnumSet.of(
            ConnectionState.INITIALIZING,
            ConnectionState.CHECKING_NETWORK,
            ConnectionState.AUTHENTICATING,
            ConnectionState.CONNECTING,
            ConnectionState.CONFIGURING,
            ConnectionState.VERIFYING);

    // Explicit transition table: legal destinations from each state.
    private static final java.util.Map<ConnectionState, Set<ConnectionState>> TRANSITIONS;

    static {
        EnumSet<ConnectionState> anything = EnumSet.allOf(ConnectionState.class);
        EnumSet<ConnectionState> fromReadyOrFailure = EnumSet.
                copyOf(anything);
        java.util.Map<ConnectionState, Set<ConnectionState>> t = new java.util.EnumMap<>(ConnectionState.class);
        t.put(ConnectionState.OFFLINE, EnumSet.of(ConnectionState.INITIALIZING, ConnectionState.OFFLINE));
        t.put(ConnectionState.INITIALIZING, EnumSet.of(
                ConnectionState.CHECKING_NETWORK, ConnectionState.OFFLINE,
                ConnectionState.ERROR, ConnectionState.AUTH_FAILED,
                ConnectionState.SERVER_UNAVAILABLE, ConnectionState.NETWORK_UNAVAILABLE,
                ConnectionState.PERMISSION_REQUIRED, ConnectionState.VPN_FAILED));
        t.put(ConnectionState.CHECKING_NETWORK, EnumSet.of(
                ConnectionState.AUTHENTICATING, ConnectionState.CONNECTING,
                ConnectionState.OFFLINE, ConnectionState.ERROR,
                ConnectionState.NETWORK_UNAVAILABLE, ConnectionState.PERMISSION_REQUIRED));
        t.put(ConnectionState.AUTHENTICATING, EnumSet.of(
                ConnectionState.CONNECTING, ConnectionState.OFFLINE,
                ConnectionState.AUTH_FAILED, ConnectionState.SERVER_UNAVAILABLE,
                ConnectionState.PERMISSION_REQUIRED, ConnectionState.ERROR));
        t.put(ConnectionState.CONNECTING, EnumSet.of(
                ConnectionState.CONFIGURING, ConnectionState.OFFLINE,
                ConnectionState.VPN_FAILED, ConnectionState.SERVER_UNAVAILABLE,
                ConnectionState.PERMISSION_REQUIRED, ConnectionState.ERROR));
        t.put(ConnectionState.CONFIGURING, EnumSet.of(
                ConnectionState.VERIFYING, ConnectionState.OFFLINE,
                ConnectionState.VPN_FAILED, ConnectionState.PERMISSION_REQUIRED,
                ConnectionState.ERROR));
        t.put(ConnectionState.VERIFYING, EnumSet.of(
                ConnectionState.CONNECTED, ConnectionState.OFFLINE,
                ConnectionState.VPN_FAILED, ConnectionState.ERROR,
                ConnectionState.RETRYING));
        for (ConnectionState fs : FAILURE_STATES) {
            t.put(fs, EnumSet.of(
                    ConnectionState.OFFLINE, ConnectionState.RETRYING,
                    ConnectionState.INITIALIZING));
        }
        t.put(ConnectionState.CONNECTED, EnumSet.of(
                ConnectionState.OFFLINE, ConnectionState.RETRYING,
                ConnectionState.INITIALIZING, ConnectionState.VPN_FAILED));
        t.put(ConnectionState.RETRYING, EnumSet.of(
                ConnectionState.INITIALIZING, ConnectionState.OFFLINE,
                ConnectionState.ERROR));
        TRANSITIONS = java.util.Collections.unmodifiableMap(t);
    }

    private final Object lock = new Object();
    private volatile ConnectionState state = ConnectionState.OFFLINE;
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();

    public ConnectionState get() {
        return state;
    }

    public void addListener(Listener listener) {
        listeners.add(Objects.requireNonNull(listener));
    }

    public void removeListener(Listener listener) {
        listeners.remove(listener);
    }

    /**
     * Move to {@code next}. Throws {@link IllegalStateException} on illegal
     * transitions so the UI can never end up in an ambiguous state.
     */
    public void transitionTo(ConnectionState next) {
        if (next == null) {
            throw new IllegalArgumentException("next must not be null");
        }
        ConnectionState from;
        synchronized (lock) {
            from = state;
            if (from == next) {
                return;
            }
            Set<ConnectionState> allowed = TRANSITIONS.get(from);
            if (allowed == null || !allowed.contains(next)) {
                throw new IllegalStateException(
                        "Illegal state transition: " + from + " -> " + next);
            }
            state = next;
        }
        AppLogger.getLogger().info(ConnectionState.class.getSimpleName(),
                "state %s -> %s", from, next);
        for (Listener l : listeners) {
            try {
                l.onStateChanged(from, next);
            } catch (RuntimeException e) {
                AppLogger.getLogger().error("StateMachine", e, "listener failed");
            }
        }
    }

    /** Used by tests to reset between scenarios. */
    public void resetForTesting() {
        synchronized (lock) {
            state = ConnectionState.OFFLINE;
        }
    }

    public static boolean isFailure(ConnectionState s) {
        return s != null && FAILURE_STATES.contains(s);
    }
}
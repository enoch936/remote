package com.company.remoteaccess.core.state;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StateMachineTest {

    @Test
    void startsOffline() {
        StateMachine sm = new StateMachine();
        assertEquals(ConnectionState.OFFLINE, sm.get());
    }

    @Test
    void happyPathTransitions() {
        StateMachine sm = new StateMachine();
        sm.transitionTo(ConnectionState.INITIALIZING);
        sm.transitionTo(ConnectionState.CHECKING_NETWORK);
        sm.transitionTo(ConnectionState.AUTHENTICATING);
        sm.transitionTo(ConnectionState.CONNECTING);
        sm.transitionTo(ConnectionState.CONFIGURING);
        sm.transitionTo(ConnectionState.VERIFYING);
        sm.transitionTo(ConnectionState.CONNECTED);
        assertEquals(ConnectionState.CONNECTED, sm.get());
    }

    @Test
    void illegalTransitionThrows() {
        StateMachine sm = new StateMachine();
        assertThrows(IllegalStateException.class,
                () -> sm.transitionTo(ConnectionState.CONNECTED));
    }

    @Test
    void initializingCanFailToAnyFailureState() {
        StateMachine sm = new StateMachine();
        sm.transitionTo(ConnectionState.INITIALIZING);
        sm.transitionTo(ConnectionState.AUTH_FAILED);
        assertTrue(sm.get().isFailure());
    }

    @Test
    void connectedCannotReEnterConfiguring() {
        StateMachine sm = new StateMachine();
        driveToConnected(sm);
        assertThrows(IllegalStateException.class,
                () -> sm.transitionTo(ConnectionState.CONFIGURING));
    }

    @Test
    void failureStatesCanResetOrRetry() {
        StateMachine sm = new StateMachine();
        driveToConnected(sm);
        sm.transitionTo(ConnectionState.VPN_FAILED);
        assertTrue(sm.get().isFailure());
        sm.transitionTo(ConnectionState.RETRYING);
        sm.transitionTo(ConnectionState.INITIALIZING);
        assertEquals(ConnectionState.INITIALIZING, sm.get());
    }

    @Test
    void connectedCanStillReconnect() {
        StateMachine sm = new StateMachine();
        driveToConnected(sm);
        sm.transitionTo(ConnectionState.RETRYING);
        sm.transitionTo(ConnectionState.INITIALIZING);
        assertEquals(ConnectionState.INITIALIZING, sm.get());
    }

    @Test
    void listenersNotifiedWithFromAndTo() {
        StateMachine sm = new StateMachine();
        List<String> seen = new ArrayList<>();
        sm.addListener((from, to) -> seen.add(from + "->" + to));
        sm.transitionTo(ConnectionState.INITIALIZING);
        sm.transitionTo(ConnectionState.CHECKING_NETWORK);
        assertEquals(2, seen.size());
        assertEquals("OFFLINE->INITIALIZING", seen.get(0));
        assertEquals("INITIALIZING->CHECKING_NETWORK", seen.get(1));
    }

    @Test
    void selfTransitionIsNoOp() {
        StateMachine sm = new StateMachine();
        sm.transitionTo(ConnectionState.OFFLINE);
        assertEquals(ConnectionState.OFFLINE, sm.get());
    }

    @Test
    void failureClassification() {
        assertTrue(ConnectionState.AUTH_FAILED.isFailure());
        assertTrue(ConnectionState.NETWORK_UNAVAILABLE.isFailure());
        assertFalse(ConnectionState.CONNECTED.isFailure());
        assertFalse(ConnectionState.OFFLINE.isFailure());
    }

    @Test
    void transientStatesExcludeFailureAndSettled() {
        StateMachine sm = new StateMachine();
        driveToConnected(sm);
        sm.transitionTo(ConnectionState.OFFLINE);
        assertFalse(sm.get().isTransient());
        assertTrue(ConnectionState.NETWORK_UNAVAILABLE.isFailure());
    }

    private static void driveToConnected(StateMachine sm) {
        sm.transitionTo(ConnectionState.INITIALIZING);
        sm.transitionTo(ConnectionState.CHECKING_NETWORK);
        sm.transitionTo(ConnectionState.AUTHENTICATING);
        sm.transitionTo(ConnectionState.CONNECTING);
        sm.transitionTo(ConnectionState.CONFIGURING);
        sm.transitionTo(ConnectionState.VERIFYING);
        sm.transitionTo(ConnectionState.CONNECTED);
    }
}
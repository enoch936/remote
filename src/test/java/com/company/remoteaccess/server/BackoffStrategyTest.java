package com.company.remoteaccess.server;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BackoffStrategyTest {

    @Test
    void delaysGrowThenCap() {
        BackoffStrategy b = new BackoffStrategy(2_000, 60_000, 10, 0);
        long a = b.nextDelayMs(0);
        long c = b.nextDelayMs(2);
        assertTrue(c > a);
        long capped = b.nextDelayMs(10); // attempt == maxRetries still returns a delay
        assertEquals(60_000, capped);
    }

    @Test
    void giveUpAfterMaxRetries() {
        BackoffStrategy b = new BackoffStrategy(1_000, 10_000, 3, 0);
        assertEquals(-1, b.nextDelayMs(4));
    }

    @Test
    void negativeAttemptBecomesZero() {
        BackoffStrategy b = new BackoffStrategy(500, 10_000, 3, 0);
        assertTrue(b.nextDelayMs(-5) > 0);
    }

    @Test
    void minimumRetriesIsOne() {
        BackoffStrategy b = new BackoffStrategy(100, 1000, 0, 0);
        assertEquals(1, b.maxRetries());
    }
}
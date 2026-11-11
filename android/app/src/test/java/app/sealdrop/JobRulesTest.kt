package app.sealdrop

import app.sealdrop.send.JobRules
import org.junit.Assert.assertEquals
import org.junit.Test

class JobRulesTest {
    @Test
    fun afterAnUnexpectedErrorTheRetryBacksOffToFourHours() {
        val minutes = (0..6).map { JobRules.afterErrorMs(it) / JobRules.MINUTE }
        assertEquals(listOf(15L, 30L, 60L, 120L, 240L, 240L, 240L), minutes)
        assertEquals(15L, JobRules.afterErrorMs(-1) / JobRules.MINUTE)
    }

    @Test
    fun theWatchdogAndTheWaitForTheFirstUnlock() {
        assertEquals(6 * 60L, JobRules.WATCHDOG_EVERY_MS / JobRules.MINUTE)
        assertEquals(5L, JobRules.UNTIL_UNLOCKED_MS / JobRules.MINUTE)
    }
}

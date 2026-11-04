package app.sealdrop.send

import androidx.test.ext.junit.runners.AndroidJUnit4
import app.sealdrop.net.Gate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL

/** The one place that opens connections (PROTOCOL.md §9.5): only HTTPS, only to the hosts from pairing. */
@RunWith(AndroidJUnit4::class)
class GateTest {
    private val gate = Gate { setOf(Gate.Host("storage.example.org", 443), Gate.Host("other.example.org", 8443)) }

    private fun refused(url: String) = try {
        gate.open(URL(url))
        false
    } catch (e: Gate.Refused) {
        true
    }

    @Test
    fun onlyPairedHostsOverHttps() {
        assertTrue(refused("http://storage.example.org/bucket/x"))
        assertTrue(refused("https://example.org/"))
        assertTrue(refused("https://storage.example.org:444/bucket/x"))
        assertTrue(refused("https://other.example.org/bucket/x")) // the right host, the wrong port
        assertTrue(refused("https://storage.example.org.evil.example/x"))
        assertFalse(refused("https://storage.example.org/bucket/x"))
        assertFalse(refused("https://STORAGE.example.org/bucket/x"))
        assertFalse(refused("https://other.example.org:8443/bucket/x"))
    }

    @Test
    fun connectionsDontFollowRedirects() {
        val c = gate.open(URL("https://storage.example.org/bucket/x"))
        assertFalse(c.instanceFollowRedirects)
        assertEquals(15_000, c.connectTimeout)
        assertEquals(60_000, c.readTimeout)
    }

    @Test
    fun nothingIsAllowedBeforePairing() {
        val empty = Gate { emptySet() }
        assertTrue(try {
            empty.open(URL("https://storage.example.org/x"))
            false
        } catch (e: Gate.Refused) {
            true
        })
    }
}

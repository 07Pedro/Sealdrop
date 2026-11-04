package app.sealdrop.core

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Names (§5, §7), manifests checked on their own, pairing MACs and the QR offer, against testvectors/vectors.json. */
@RunWith(AndroidJUnit4::class)
class ManifestsTest {
    private val v = TestFiles.vectors

    @Test
    fun names() {
        val names = v["names"].obj()
        val checks = mapOf<String, (String) -> Boolean>(
            "app" to Manifests::goodApp, "delivery" to Manifests::goodDelivery, "path" to Manifests::goodPath,
            "labels" to { Manifests.goodLabel(it) },
        )
        for ((kind, check) in checks) {
            for (name in names[kind].obj()["good"].list()) assertTrue("$kind good: $name", check(name.str()))
            for (name in names[kind].obj()["bad"].list()) assertFalse("$kind bad: $name", check(name.str()))
        }
    }

    @Test
    fun clashes() {
        for (case in v["names"].obj()["clashes"].list().map { it.obj() }) {
            assertEquals(case.toString(), case["clash"], Manifests.pathsClash(case["paths"].list().map { it.str() }))
        }
    }

    @Test
    fun bundleManifests() {
        for (case in v["manifests"].obj()["bundles"].list().map { it.obj() }) {
            val raw = Encoding.unb64url(case["text"])
            val id = case["id"].str()
            if ("reject" in case) {
                val e = assertThrows(id, Rejected::class.java) { Manifests.checkBundle(Json.parse(raw), case["n"].long(), raw.size.toLong()) }
                assertEquals(id, case["reject"], e.reason)
            } else {
                val deliveries = Manifests.checkBundle(Json.parse(raw), case["n"].long(), raw.size.toLong())
                assertEquals(id, case["problems"], deliveries.map { it.problem })
            }
        }
    }

    @Test
    fun pairManifests() {
        for (case in v["manifests"].obj()["pairs"].list().map { it.obj() }) {
            val manifest = Json.parse(Encoding.unb64url(case["text"]))
            val id = case["id"].str()
            if (case["valid"] == true) assertEquals(id, case["check"], Manifests.checkPairNames(Manifests.parsePair(manifest)))
            else assertThrows(id, Rejected::class.java) { Manifests.parsePair(manifest) }
        }
    }

    @Test
    fun receiptManifests() {
        val own = listOf(Encoding.unhex(v["manifests"].obj()["own_key_id"]))
        for (case in v["manifests"].obj()["receipts"].list().map { it.obj() }) {
            val manifest = Json.parse(Encoding.unb64url(case["text"]))
            val id = case["id"].str()
            if (case["valid"] == true) Receipts.parse(manifest, own)
            else assertThrows(id, FormatException::class.java) { Receipts.parse(manifest, own) }
        }
    }

    @Test
    fun receiptFieldsThePhoneReliesOn() {
        val own = listOf(Encoding.unhex(v["manifests"].obj()["own_key_id"]))
        val good = v["manifests"].obj()["receipts"].list().map { it.obj() }.first { it["id"] == "receipt" }
        val manifest = Json.parse(Encoding.unb64url(good["text"])).obj()
        val report = Receipts.parse(manifest, own) as Receipts.Report
        assertEquals(1L, report.stored.single().deliveries.single().seq)
        assertNull(report.status.lastBackup)
        fun without(vararg path: String): Map<*, *> {
            val copy = Json.parse(Json.write(manifest)).obj()
            var m: Any? = copy
            for (key in path.dropLast(1)) m = if (m is List<*>) m[key.toInt()] else (m as Map<*, *>)[key]
            @Suppress("UNCHECKED_CAST")
            (m as MutableMap<String, Any?>).remove(path.last())
            return copy
        }
        for (path in listOf(listOf("status"), listOf("stored"), listOf("status", "instance"), listOf("status", "last_backup"),
            listOf("stored", "0", "received"), listOf("stored", "0", "deliveries", "0", "digest"))) {
            assertThrows(path.toString(), FormatException::class.java) { Receipts.parse(without(*path.toTypedArray()), own) }
        }
    }

    @Test
    fun macsAndFingerprint() {
        val p = v["pairing"].obj()
        val offer = p["offer"].obj()
        val pairing = Encoding.unb64url(offer["pairing"])
        val code = Encoding.unb64url(offer["code"])
        for (m in p["macs"].list().map { it.obj() }) {
            val replaces = m["replaces"]?.let { Encoding.unhex(it) }
            val transcript = Pairing.macTranscript(pairing, TestFiles.public("collector_open"), TestFiles.public("collector_sign"),
                TestFiles.public("sender_sign"), TestFiles.public("sender_open"), replaces)
            assertEquals(m["transcript"], Encoding.hex(transcript))
            assertEquals(m["mac"], Encoding.hex(Pairing.pairMac(code, pairing, transcript)))
        }
        assertEquals(p["fingerprint"], Pairing.fingerprint(pairing, TestFiles.public("collector_open"),
            TestFiles.public("collector_sign"), TestFiles.public("sender_sign"), TestFiles.public("sender_open")))
    }

    @Test
    fun offers() {
        val now = v["pairing"].obj()["offer"].obj()["expires"].long() - 1
        for (case in v["offers"].list().map { it.obj() }) {
            val id = case["id"].str()
            if (case["valid"] == true) {
                val offer = Pairing.checkOffer(case["offer"], now)
                assertTrue(id, offer.ack.endpoint.startsWith("https://"))
                assertFalse("the key never shows in a log", offer.toString().contains(offer.up.secret))
            } else {
                assertThrows(id, FormatException::class.java) { Pairing.checkOffer(case["offer"], now) }
            }
        }
    }

    @Test
    fun expiredOffer() {
        val offer = v["pairing"].obj()["offer"].obj()
        val expires = offer["expires"].long()
        Pairing.checkOffer(offer, expires + Pairing.ALLOWANCE_MS)
        assertThrows(FormatException::class.java) { Pairing.checkOffer(offer, expires + Pairing.ALLOWANCE_MS + 1) }
    }

    @Test
    fun ackTakesWhatItLeavesOutFromUp() {
        val offer = Pairing.checkOffer(v["pairing"].obj()["offer"], 0)
        assertEquals(offer.up.bucket, offer.ack.bucket)
        assertEquals("ack/", offer.ack.prefix)
        assertEquals("EXAMPLE-RECEIPTS-KEY-ID", offer.ack.keyId)
    }
}

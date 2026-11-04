package app.sealdrop.send

import android.os.ParcelFileDescriptor
import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.sealdrop.Engine
import app.sealdrop.api.FileOffer
import app.sealdrop.api.Sealdrop
import app.sealdrop.core.Encoding
import app.sealdrop.data.Db
import app.sealdrop.data.Vault
import app.sealdrop.net.S3Error
import app.sealdrop.pair.Pairer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.IOException

/**
 * The phone's whole flow (PROTOCOL.md §6, §7, §9) against storage in memory and a stand-in collector: pairing, the
 * handover's checks, packing, resumable uploads, receipts and their matching, strikes, final states, lost deliveries,
 * two collectors, holds and the warnings. Nothing here touches the network, Sealdrop's own data or its keys.
 */
@RunWith(AndroidJUnit4::class)
class FlowTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val tag = Encoding.hex(Encoding.randomBytes(4))
    private val dir = File(context.cacheDir, "flow-$tag")
    private val dbName = "flow-$tag.db"
    private var now = 1_790_000_000_000L
    private lateinit var engine: Engine
    private lateinit var handover: Handover
    private val up = FakeUp()
    private val ack = FakeAck()
    private val collector = FakeCollector(up, ack) { now }
    private val asked = ArrayList<String>()
    private val me = Process.myUid()
    private val app = context.packageName

    @Before
    fun setUp() {
        dir.mkdirs()
        engine = Engine(context, Db(context, dbName), Vault(context, File(dir, "secrets.bin"), "sealdrop-test-$tag."), dir) { now }
        engine.upStore = { up }
        engine.ackStore = { ack }
        engine.later = object : Jobs.Later {
            override fun sendSoon() { asked += "sendSoon" }
            override fun sendNow() { asked += "sendNow" }
            override fun afterHold() { asked += "afterHold" }
            override fun pairing() { asked += "pairing" }
            override fun ensure() { asked += "ensure" }
            override fun cancelAll() { asked += "cancelAll" }
        }
        handover = Handover(engine)
        Approvals.approve(engine, Approvals.Request(app, Approvals.certificateOf(engine, app)!!, now))
    }

    @After
    fun tearDown() {
        engine.vault.wipe()
        engine.db.close()
        context.deleteDatabase(dbName)
        dir.deleteRecursively()
    }

    // --- helpers ----------------------------------------------------------------------------------------------------

    private fun pair(label: String = "Test phone"): String {
        val pairer = Pairer(engine)
        val fingerprint = pairer.start(pairer.read(collector.offerText()), label)
        assertEquals(Pairer.Poll.WAITING, pairer.poll()) // sends the request
        assertEquals(fingerprint, collector.pair())
        assertEquals(Pairer.Poll.PAIRED, pairer.poll())
        return fingerprint
    }

    private fun sender() = collector.senders.values.last()

    private fun file(content: ByteArray): File = File(dir, "offer-" + Encoding.hex(Encoding.randomBytes(6))).apply { writeBytes(content) }

    private fun offer(path: String, content: ByteArray, sha: String = Encoding.hex(Encoding.sha256(content))) = FileOffer().apply {
        this.path = path
        size = content.size.toLong()
        sha256 = sha
        file = ParcelFileDescriptor.open(file(content), ParcelFileDescriptor.MODE_READ_ONLY)
    }

    private fun handOver(delivery: String, files: Map<String, ByteArray>, network: Int = Sealdrop.NETWORK_MOBILE): Int {
        val begun = handover.begin(me, delivery, network)
        if (begun.code != Sealdrop.OK) return begun.code
        val added = handover.add(me, begun.handle, files.map { (p, c) -> offer(p, c) }.toTypedArray())
        if (added.code != Sealdrop.OK) return added.code
        return handover.commit(me, begun.handle)
    }

    private fun state(delivery: String) = handover.status(me, arrayOf(delivery))!!.single().state

    private fun send(net: Outbox.Net = Outbox.Net.WIFI, beforePart: (Int) -> Unit = {}) =
        Outbox(engine, up, { false }, beforePart).run(net)

    private fun receipts() = Inbox(engine, ack).run()

    private fun bits() = Warnings.bits(engine, app)

    private fun copies() = File(dir, "copies").list()?.size ?: 0

    // --- pairing ----------------------------------------------------------------------------------------------------

    @Test
    fun pairsWithTheCollector() {
        assertEquals(Sealdrop.NOT_PAIRED, handover.begin(me, "d1", 1).code)
        assertTrue(bits() and Sealdrop.WARNING_NOT_PAIRED != 0)
        val fingerprint = pair()
        assertTrue(Regex("[A-Z2-7]{4}( [A-Z2-7]{4}){3}").matches(fingerprint))
        assertEquals(0, bits())
        val info = handover.info(me)!!
        assertTrue(info.paired)
        assertEquals(fingerprint, info.fingerprint)
        assertEquals(4_286_578_688L, info.maxDeliveryBytes)
        assertTrue("the pairing job was asked for", "pairing" in asked)
    }

    @Test
    fun expiredOrForeignCodesAreRefused() {
        val pairer = Pairer(engine)
        val text = collector.offerText()
        now += 16 * 60_000 // 10 minutes plus the 5 minutes' allowance, and more
        assertEquals("This QR code has expired. Start pairing again on your server.",
            runCatching { pairer.read(text) }.exceptionOrNull()?.message)
        assertEquals("This isn't a Sealdrop pairing code.", runCatching { pairer.read("https://example.org/") }.exceptionOrNull()?.message)
        assertEquals("This isn't a Sealdrop pairing code.", runCatching { pairer.read("{\"type\":\"other\"}") }.exceptionOrNull()?.message)
    }

    // --- handing over -----------------------------------------------------------------------------------------------

    @Test
    fun deliveryTravelsAndIsPickedUp() {
        pair()
        val content = mapOf("track/a.gpx" to "a".repeat(5000).toByteArray(), "track/b.txt" to "b".toByteArray())
        assertEquals(Sealdrop.OK, handOver("ride-1", content))
        assertTrue("sendSoon" in asked)
        assertEquals(Sealdrop.STATE_QUEUED, state("ride-1"))
        assertEquals(1, handover.info(me)!!.waiting)
        assertEquals(1, send().uploads)
        assertEquals(Sealdrop.STATE_IN_INBOX, state("ride-1"))
        assertTrue(File(dir, "outbox").list()!!.isEmpty())
        collector.run()
        assertEquals(1, receipts())
        val st = handover.status(me, arrayOf("ride-1"))!!.single()
        assertEquals(Sealdrop.STATE_PICKED_UP, st.state)
        assertEquals(now, st.time)
        assertEquals(0, copies())
        assertEquals(0, handover.info(me)!!.waiting)
        assertEquals(now, handover.info(me)!!.lastPickup)
        // handed over again with the same bytes: already have it; other bytes: a conflict
        assertEquals(Sealdrop.ALREADY_HAVE, handOver("ride-1", content))
        assertEquals(Sealdrop.CONFLICT, handOver("ride-1", mapOf("track/a.gpx" to "other".toByteArray())))
        // a replayed receipt changes nothing
        ack.objects["replayed"] = ack.objects.values.last()
        receipts()
        assertEquals(Sealdrop.STATE_PICKED_UP, state("ride-1"))
    }

    @Test
    fun handoverChecksItsInput() {
        pair()
        val h = handover.begin(me, "d1", 1).handle
        assertEquals(Sealdrop.BAD_REQUEST, handover.add(me, h, arrayOf(offer("../x", "x".toByteArray()))).code)
        val reserved = handover.add(me, h, arrayOf(offer("ok.txt", "x".toByteArray()), offer("CON.txt", "y".toByteArray())))
        assertEquals(Sealdrop.BAD_REQUEST, reserved.code)
        assertEquals(1, reserved.index)
        assertEquals(Sealdrop.CHECKSUM_WRONG, handover.add(me, h, arrayOf(offer("a.txt", "x".toByteArray(), "0".repeat(64)))).code)
        val wrongSize = offer("a.txt", "xyz".toByteArray()).apply { size = 2 }
        assertEquals(Sealdrop.BAD_REQUEST, handover.add(me, h, arrayOf(wrongSize)).code)
        val pipe = ParcelFileDescriptor.createPipe()
        pipe[1].close()
        val notRegular = FileOffer().apply { path = "p.txt"; size = 0; sha256 = Encoding.hex(Encoding.sha256(ByteArray(0))); file = pipe[0] }
        assertEquals(Sealdrop.BAD_REQUEST, handover.add(me, h, arrayOf(notRegular)).code)
        assertEquals(Sealdrop.BAD_REQUEST, handover.add(me, h, Array(101) { offer("f$it", ByteArray(1)) }).code)
        assertEquals(Sealdrop.UNKNOWN_HANDLE, handover.add(me, "00".repeat(16), arrayOf(offer("a", ByteArray(1)))).code)
        // another UID: the caller check comes first, before its handle is looked at
        assertEquals(Sealdrop.NOT_APPROVED, handover.add(me + 1, h, arrayOf(offer("a", ByteArray(1)))).code)
        assertEquals(Sealdrop.BAD_REQUEST, handover.commit(me, h)) // no files: nothing kept, the handle ended
        assertEquals(Sealdrop.UNKNOWN_HANDLE, handover.commit(me, h))
        assertEquals(Sealdrop.BAD_REQUEST, handover.begin(me, "bad/name", 1).code)
        assertEquals(Sealdrop.BAD_REQUEST, handover.begin(me, "d2", 3).code)
        // add is all or nothing: the good first file of a failing call isn't kept
        val h2 = handover.begin(me, "d3", 1).handle
        handover.add(me, h2, arrayOf(offer("a.txt", "a".toByteArray()), offer("b.txt", "b".toByteArray(), "1".repeat(64))))
        assertEquals(Sealdrop.OK, handover.add(me, h2, arrayOf(offer("a.txt", "a".toByteArray()))).code)
        assertEquals(Sealdrop.OK, handover.commit(me, h2))
        // a new begin for the same delivery ends the unfinished handle
        val h3 = handover.begin(me, "d4", 1).handle
        handover.begin(me, "d4", 1)
        assertEquals(Sealdrop.UNKNOWN_HANDLE, handover.commit(me, h3))
        assertEquals(1, File(dir, "incoming").list()!!.size) // only the new handle's folder
        assertNull(handover.status(me, Array(501) { "d$it" }))
    }

    @Test
    fun unapprovedCallersAreRefusedAndAskedOnce() {
        pair()
        engine.db.exec("DELETE FROM approvals")
        assertEquals(Sealdrop.NOT_APPROVED, handover.begin(me, "d1", 1).code)
        assertEquals(Sealdrop.NOT_APPROVED, handover.sendNow(me, false))
        assertNull(handover.info(me))
        assertEquals(0, handover.status(me, arrayOf("d1"))!!.size)
        assertEquals(listOf(app), Approvals.pending(engine).map { it.app })
        Approvals.refuse(engine, Approvals.pending(engine).single())
        handover.begin(me, "d1", 1)
        assertTrue("a refused app isn't asked about again", Approvals.pending(engine).isEmpty())
        now += Approvals.QUIET_MS + 1
        handover.begin(me, "d1", 1)
        assertEquals(1, Approvals.pending(engine).size)
    }

    // --- strikes and rejections ---------------------------------------------------------------------------------------

    @Test
    fun aStrikeSendsItAgainAloneAndTwoFailIt() {
        pair()
        handOver("d1", mapOf("a.txt" to "one".toByteArray()))
        handOver("d2", mapOf("a.txt" to "two".toByteArray()))
        send()
        collector.rejectDelivery[app to "d1"] = "bad-file"
        collector.run()
        receipts()
        assertEquals(Sealdrop.STATE_QUEUED, state("d1"))
        assertEquals(Sealdrop.STATE_PICKED_UP, state("d2"))
        assertTrue(bits() and Sealdrop.WARNING_REJECTED != 0)
        assertEquals(1, send().uploads)
        collector.rejectDelivery[app to "d1"] = "bad-file"
        collector.run()
        receipts()
        assertEquals(Sealdrop.STATE_FAILED, state("d1"))
        assertTrue(bits() and Sealdrop.WARNING_FAILED != 0)
        assertEquals(0, handover.info(me)!!.waiting)
        // the owner sends it again: strikes from 0
        Owner.sendAgain(engine, app, "d1")
        assertEquals(Sealdrop.STATE_QUEUED, state("d1"))
        send()
        collector.run()
        receipts()
        assertEquals(Sealdrop.STATE_PICKED_UP, state("d1"))
        assertEquals(0, bits() and Sealdrop.WARNING_FAILED)
    }

    @Test
    fun discardKeepsTheFailedState() {
        pair()
        handOver("d1", mapOf("a.txt" to "one".toByteArray()))
        repeat(2) {
            send()
            collector.rejectDelivery[app to "d1"] = "bad-name"
            collector.run()
            receipts()
        }
        assertEquals(Sealdrop.STATE_FAILED, state("d1"))
        Owner.discard(engine, app, "d1")
        assertEquals(Sealdrop.STATE_FAILED, state("d1"))
        assertEquals(0, copies())
        assertEquals(0, bits() and Sealdrop.WARNING_FAILED)
    }

    @Test
    fun aDamagedHeaderIsMatchedByNameAndSize() {
        pair()
        handOver("d1", mapOf("a.txt" to "one".toByteArray()))
        send()
        val (name, data) = up.objects.entries.single()
        up.objects[name] = data.copyOf().also { it[10] = (it[10].toInt() xor 1).toByte() }
        collector.run()
        receipts()
        assertEquals("a strike: sent again, alone", Sealdrop.STATE_QUEUED, state("d1"))
        send()
        collector.run()
        receipts()
        assertEquals(Sealdrop.STATE_PICKED_UP, state("d1"))
    }

    @Test
    fun aTamperedBodyIsNotTakenForThisPhonesUpload() {
        pair()
        handOver("d1", mapOf("a.txt" to "one".toByteArray()))
        send()
        val (name, data) = up.objects.entries.single()
        up.objects[name] = data.copyOf().also { it[400] = (it[400].toInt() xor 1).toByte() }
        collector.run()
        receipts()
        // The rejection names another SHA-256: nothing of this phone's matches; it waits (re-sent after 60 days).
        assertEquals(Sealdrop.STATE_IN_INBOX, state("d1"))
        assertEquals(0, bits() and Sealdrop.WARNING_REJECTED)
        now += Outbox.RESEND_MS + 1
        assertEquals(1, send().uploads)
        collector.run()
        receipts()
        assertEquals(Sealdrop.STATE_PICKED_UP, state("d1"))
    }

    @Test
    fun wholeFileRejectionsOfSeveralRepackThem() {
        pair()
        handOver("d1", mapOf("a.txt" to "one".toByteArray()))
        handOver("d2", mapOf("a.txt" to "two".toByteArray()))
        send()
        val name = up.objects.keys.single()
        up.objects.clear()
        collector.report(sender(), emptyList(), listOf(mapOf("name" to name, "size" to 1L, "reason" to "damaged", "at" to now)))
        receipts() // the size doesn't match: no match
        assertEquals(Sealdrop.STATE_IN_INBOX, state("d1"))
        val size = engine.db.long("SELECT size FROM uploads WHERE name = ?", name)
        collector.report(sender(), emptyList(), listOf(mapOf("name" to name, "size" to size, "reason" to "bad-content", "at" to now)))
        receipts()
        assertEquals(Sealdrop.STATE_QUEUED, state("d1"))
        assertEquals(Sealdrop.STATE_QUEUED, state("d2"))
        assertEquals("after bad-content each goes alone", 2, send().uploads)
        collector.run()
        receipts()
        assertEquals(Sealdrop.STATE_PICKED_UP, state("d1"))
        assertEquals(Sealdrop.STATE_PICKED_UP, state("d2"))
    }

    // --- duplicates, conflicts, re-sends -------------------------------------------------------------------------------

    @Test
    fun aResentDeliveryComesBackAsDuplicate() {
        pair()
        handOver("d1", mapOf("a.txt" to "one".toByteArray()))
        send()
        now += Outbox.RESEND_MS + 1
        assertEquals(1, send().uploads)
        assertEquals(2, up.objects.size)
        collector.run()
        receipts()
        assertEquals(Sealdrop.STATE_PICKED_UP, state("d1"))
        assertEquals("both uploads are forgotten", 0L, engine.db.long("SELECT COUNT(*) FROM uploads"))
    }

    @Test
    fun aConflictAtTheCollectorIsFinal() {
        pair()
        collector.stored[app to "d1"] = "0".repeat(64) to 99
        handOver("d1", mapOf("a.txt" to "one".toByteArray()))
        send()
        collector.run()
        receipts()
        assertEquals(Sealdrop.STATE_CONFLICT, state("d1"))
        assertEquals(0, copies())
    }

    // --- uploads ------------------------------------------------------------------------------------------------------

    @Test
    fun aCutUploadResumesWithTheNextPart() {
        pair()
        val big = ByteArray(15 shl 20) { (it % 251).toByte() } // sealed: 16 MiB and a little, so 3 parts
        handOver("big", mapOf("big.bin" to big))
        up.calls.clear() // the pairing request
        try {
            send { if (it == 2) throw IOException("cut") }
            error("the cut should end the run")
        } catch (e: IOException) {
            // the connection was cut after part 1
        }
        assertEquals(Sealdrop.STATE_UPLOADING, state("big"))
        assertEquals(listOf("create", "part1"), up.calls)
        send()
        assertEquals(listOf("create", "part1", "part2", "part3", "complete"), up.calls)
        collector.run()
        receipts()
        assertEquals(Sealdrop.STATE_PICKED_UP, state("big"))
    }

    @Test
    fun aForgottenMultipartStartsOver() {
        pair()
        handOver("big", mapOf("big.bin" to ByteArray(9 shl 20)))
        runCatching { send { if (it == 2) throw IOException("cut") } }
        up.multiparts.clear() // the provider's lifecycle rule ended it
        send()
        assertEquals(Sealdrop.STATE_IN_INBOX, state("big"))
        assertEquals(2, up.calls.count { it == "create" })
    }

    @Test
    fun mobileDataTakesOnlyWhatMayUseIt() {
        pair()
        handOver("wifi", mapOf("a.txt" to "w".toByteArray()), Sealdrop.NETWORK_WIFI_ONLY)
        handOver("small", mapOf("a.txt" to "s".toByteArray()))
        handOver("large", mapOf("a.bin" to ByteArray(11 shl 20)))
        val r = send(Outbox.Net.MOBILE)
        assertEquals(1, r.uploads)
        assertTrue(r.waitingForWifi)
        assertEquals(Sealdrop.STATE_IN_INBOX, state("small"))
        assertEquals(Sealdrop.STATE_QUEUED, state("wifi"))
        assertEquals(Sealdrop.STATE_QUEUED, state("large"))
        assertEquals(Sealdrop.OK, handover.sendNow(me, true)) // the app lets its Wi-Fi-only deliveries use mobile data
        assertEquals(1, send(Outbox.Net.MOBILE).uploads)
        assertEquals(Sealdrop.STATE_IN_INBOX, state("wifi"))
        assertEquals(1, send(Outbox.Net.WIFI).uploads)
        assertEquals(Sealdrop.STATE_IN_INBOX, state("large"))
    }

    @Test
    fun holdsStopSending() {
        pair()
        handOver("d1", mapOf("a.txt" to "one".toByteArray()))
        handover.hold(me, 5000)
        assertEquals(now + 900_000, Holds.endsAt(engine)) // clamped to 900 seconds
        assertTrue(Holds.held(engine))
        assertTrue(runCatching { Outbox(engine, up, { Holds.held(engine) }).run(Outbox.Net.WIFI) }.exceptionOrNull() is Outbox.Stopped)
        assertEquals(Sealdrop.STATE_QUEUED, state("d1"))
        handover.release(me)
        assertFalse(Holds.held(engine))
        assertTrue("afterHold" in asked)
        handover.hold(me, 60)
        now += 61_000
        assertFalse("a hold runs out", Holds.held(engine))
        assertEquals(0, bits() and Sealdrop.WARNING_HELD_LONG)
        repeat(110) { // one app holding for a day, renewing its hold with no gap
            handover.hold(me, 900)
            now += 800_000
        }
        assertTrue(bits() and Sealdrop.WARNING_HELD_LONG != 0)
    }

    // --- warnings from the storage ------------------------------------------------------------------------------------

    @Test
    fun storageAnswersSetAndClearWarnings() {
        pair()
        handOver("d1", mapOf("a.txt" to "one".toByteArray()))
        up.fault = { throw S3Error(403, "AccessDenied", "Transaction cap exceeded, see the Caps & Alerts page") }
        runCatching { send() }
        assertTrue(bits() and Sealdrop.WARNING_STORAGE_CAP != 0)
        assertEquals(0, bits() and Sealdrop.WARNING_KEY_REFUSED)
        up.fault = { throw S3Error(403, "InvalidAccessKeyId", "The key is not valid") }
        runCatching { send() }
        assertTrue(bits() and Sealdrop.WARNING_KEY_REFUSED != 0)
        up.fault = { throw S3Error(403, "RequestTimeTooSkewed", "The difference is too large") }
        runCatching { send() }
        assertTrue(bits() and Sealdrop.WARNING_CLOCK != 0)
        up.fault = {}
        send()
        assertEquals(0, bits() and (Sealdrop.WARNING_STORAGE_CAP or Sealdrop.WARNING_KEY_REFUSED or Sealdrop.WARNING_CLOCK))
    }

    // --- receipts -----------------------------------------------------------------------------------------------------

    @Test
    fun junkAndForeignReceiptsAreIgnored() {
        pair()
        ack.objects["junk1"] = Encoding.randomBytes(4096 + 152 + 16 + 64) // a possible size
        ack.objects["junk2"] = Encoding.randomBytes(1000) // an impossible one
        receipts()
        assertEquals(0, bits())
        // sealed for this phone, but signed by someone else: "can't read receipts" at once
        collector.receipt(sender(), mapOf("v" to 1L, "type" to "receipt"), by = Ed25519TestSigner())
        receipts()
        assertTrue(bits() and Sealdrop.WARNING_CANT_READ_RECEIPTS != 0)
        collector.run()
        receipts()
        assertEquals("a good receipt clears it", 0, bits() and Sealdrop.WARNING_CANT_READ_RECEIPTS)
        assertEquals("names are remembered", 0, receipts())
    }

    @Test
    fun theNewestStatusCounts() {
        pair()
        collector.warnings = listOf("disk-full", "something-new")
        collector.run()
        receipts()
        assertTrue(bits() and Sealdrop.WARNING_COLLECTOR_PROBLEM != 0)
        val older = now
        now += 1000
        collector.warnings = emptyList()
        collector.maxSealed = 64L shl 20
        collector.run()
        receipts()
        assertEquals(0, bits() and Sealdrop.WARNING_COLLECTOR_PROBLEM)
        assertEquals(56L shl 20, handover.info(me)!!.maxDeliveryBytes) // L = 60 MiB fits, less 4 MiB
        // a replayed older receipt doesn't bring the old status back
        val saved = now
        now = older
        collector.warnings = listOf("disk-full")
        collector.run()
        now = saved
        receipts()
        assertEquals(0, bits() and Sealdrop.WARNING_COLLECTOR_PROBLEM)
    }

    @Test
    fun lostDeliveriesGoBackToTheirApps() {
        pair()
        for (d in listOf("d1", "d2", "d3")) {
            handOver(d, mapOf("a.txt" to d.toByteArray()))
            send()
            collector.run()
            receipts()
            now += 60_000
        }
        assertEquals(Sealdrop.STATE_PICKED_UP, state("d3"))
        // the collector was restored from a backup that has only d1
        collector.report(sender(), emptyList(), statusSeq = 1)
        receipts()
        assertEquals(Sealdrop.STATE_PICKED_UP, state("d1"))
        assertEquals(Sealdrop.STATE_UNKNOWN, state("d2"))
        assertEquals(Sealdrop.STATE_UNKNOWN, state("d3"))
        assertTrue(bits() and Sealdrop.WARNING_LOST != 0)
        assertEquals(now, handover.info(me)!!.lostAt)
        // handed over again with the same bytes, they travel again
        assertEquals(Sealdrop.OK, handOver("d2", mapOf("a.txt" to "d2".toByteArray())))
    }

    @Test
    fun twoCollectorsWarnAndKeepEverything() {
        pair()
        val a = collector.instance
        val b = Encoding.randomBytes(16)
        handOver("d1", mapOf("a.txt" to "one".toByteArray()))
        send()
        collector.run()
        receipts()
        for (i in listOf(b, a)) {
            now += 60_000
            collector.instance = i
            collector.report(sender(), emptyList())
            receipts()
        }
        assertTrue(bits() and Sealdrop.WARNING_TWO_COLLECTORS != 0)
        now += 60_000
        collector.report(sender(), emptyList(), statusSeq = 0) // would be a loss with one collector
        receipts()
        assertEquals("nothing goes back while two collectors are seen", Sealdrop.STATE_PICKED_UP, state("d1"))
        now += 8 * 86_400_000L
        assertEquals(0, bits() and Sealdrop.WARNING_TWO_COLLECTORS)
    }

    @Test
    fun pairingAgainResealsWhatIsNotConfirmed() {
        val first = pair()
        val old = sender()
        handOver("d1", mapOf("a.txt" to "one".toByteArray()))
        send()
        assertEquals(Sealdrop.STATE_IN_INBOX, state("d1"))
        up.objects.clear() // lost in the old inbox
        val second = pair("Test phone 2")
        assertNotEquals(first, second)
        assertEquals(Sealdrop.STATE_QUEUED, state("d1"))
        assertEquals(2, engine.ownKeyIds().size)
        send()
        collector.run()
        receipts()
        assertEquals(Sealdrop.STATE_PICKED_UP, state("d1"))
        // the old key's receipts are still read for 60 days
        collector.report(old, emptyList())
        assertEquals(1, receipts())
        now += 61 * 86_400_000L
        assertEquals(1, engine.ownKeyIds().size)
    }

    @Test
    fun unpairingDeletesKeysAndCopies() {
        pair()
        handOver("d1", mapOf("a.txt" to "one".toByteArray()))
        Pairer(engine).unpair()
        assertNull(engine.paired())
        assertEquals(0, copies())
        assertEquals(Sealdrop.STATE_UNKNOWN, state("d1"))
        assertEquals(Sealdrop.NOT_PAIRED, handover.begin(me, "d2", 1).code)
    }
}

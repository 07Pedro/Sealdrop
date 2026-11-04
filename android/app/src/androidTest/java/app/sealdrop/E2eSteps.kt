package app.sealdrop

import android.graphics.BitmapFactory
import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.sealdrop.api.Sealdrop
import app.sealdrop.net.Gate
import app.sealdrop.pair.Pairer
import app.sealdrop.pair.Qr
import app.sealdrop.send.Approvals
import app.sealdrop.send.Inbox
import app.sealdrop.send.Sync
import app.sealdrop.send.Warnings
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.IOException
import java.net.InetAddress

/**
 * The phone's steps of the end-to-end check (tools/e2e/run.py), one per call of `am instrument`, on Sealdrop's real
 * state: the harness runs them in order between the collector's steps. Skipped unless the harness passes `e2e=1`.
 * Results go back as instrumentation status lines (`key=value`); no key or file content is ever reported.
 */
@RunWith(AndroidJUnit4::class)
class E2eSteps {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val args = InstrumentationRegistry.getArguments()
    private val context = instrumentation.targetContext
    private val engine by lazy { Engine.get(context) }

    private fun arg(name: String): String = args.getString(name) ?: error("missing argument $name")
    private fun report(vararg values: Pair<String, Any?>) =
        instrumentation.sendStatus(2, Bundle().apply { for ((k, v) in values) putString(k, v.toString()) })

    private fun e2e() = assumeTrue("only for tools/e2e", args.getString("e2e") == "1")

    /** Reads the QR code the harness put into Sealdrop's private files (and deletes it at once), then starts pairing. */
    @Test
    fun pairFromQr() {
        e2e()
        val file = File(context.filesDir, "e2e-qr.png")
        val bitmap = BitmapFactory.decodeFile(file.path)
        file.delete()
        assertNotNull("no QR image", bitmap)
        val text = Qr.decode(bitmap) ?: error("no QR code found in the image")
        val pairer = Pairer(engine)
        val fingerprint = pairer.start(pairer.read(text), args.getString("label") ?: "Emulator")
        report("fingerprint" to fingerprint)
        assertEquals(Pairer.Poll.WAITING, pairer.poll()) // sends the request
        report("request" to "sent")
    }

    @Test
    fun waitPaired() {
        e2e()
        repeat(40) {
            when (Pairer(engine).poll()) {
                Pairer.Poll.PAIRED -> return report("paired" to engine.paired()!!.fingerprint)
                Pairer.Poll.WAITING -> Thread.sleep(3000)
                else -> error("pairing ended without the paired receipt")
            }
        }
        error("no paired receipt within 2 minutes")
    }

    @Test
    fun approve() {
        e2e()
        val request = Approvals.pending(engine).firstOrNull { it.app == arg("app") } ?: error("no request from ${arg("app")}")
        report("cert_end" to request.cert.takeLast(8))
        Approvals.approve(engine, request)
    }

    /** A sync run as the job does it: upload, then receipts. `cut`: the connection drops before that part. */
    @Test
    fun sync() {
        e2e()
        val cut = args.getString("cut")?.toInt()
        val parts = ArrayList<Int>()
        val result = Sync.run(engine, send = true, stop = { false }) { n ->
            if (n == cut) throw IOException("cut by the end-to-end check")
            parts += n
        }
        report("parts" to parts.joinToString(","), "retry" to (result.retryIn != null))
        if (cut == null) assertNull("the run failed", result.retryIn) else assertNotNull("the cut didn't stop the run", result.retryIn)
    }

    @Test
    fun receipts() {
        e2e()
        val handled = Inbox(engine, engine.ackStore(engine.paired()!!)).run()
        report("receipts" to handled)
    }

    /** Every delivery's state, the warnings, and what's still pending. */
    @Test
    fun show() {
        e2e()
        val db = engine.db
        val rows = db.query("SELECT delivery, state, strikes, alone FROM deliveries ORDER BY delivery") {
            "${it.getString(0)}:${it.getInt(1)}:${it.getInt(2)}:${it.getInt(3)}"
        }
        report(
            "deliveries" to rows.joinToString(" "),
            "warnings" to Warnings.bits(engine, null),
            "uploads" to db.long("SELECT COUNT(*) FROM uploads WHERE state = 0"),
            "copies" to (File(context.filesDir, "copies").list()?.size ?: 0),
            "outbox" to (File(context.filesDir, "outbox").list()?.size ?: 0),
        )
    }

    /** As if Sealdrop had lost a delivery (a reinstall): its row goes, so the app's next hand-over is new. */
    @Test
    fun forget() {
        e2e()
        engine.db.exec("DELETE FROM deliveries WHERE app = ? AND delivery = ?", arg("app"), arg("delivery"))
        engine.db.exec("DELETE FROM files WHERE app = ? AND delivery = ?", arg("app"), arg("delivery"))
    }

    /** Moves the deliveries in the inbox 61 days back, so the next run seals them again (§9.2). */
    @Test
    fun age() {
        e2e()
        engine.db.exec("UPDATE deliveries SET inbox_at = inbox_at - ? WHERE state = ?", 61 * Warnings.DAY, Sealdrop.STATE_IN_INBOX)
    }

    /** The storage host's addresses as the phone sees them, for the harness's look at the connections. */
    @Test
    fun resolve() {
        e2e()
        val host = Gate.hostOf(engine.paired()!!.up.endpoint).name
        report("addresses" to InetAddress.getAllByName(host).joinToString(",") { it.hostAddress ?: "" })
    }

    @Test
    fun gateRefusesOthers() {
        e2e()
        for (url in listOf("https://example.org/", "http://" + Gate.hostOf(engine.paired()!!.up.endpoint).name + "/")) {
            assertTrue(url, runCatching { engine.gate.open(java.net.URL(url)) }.exceptionOrNull() is Gate.Refused)
        }
    }
}

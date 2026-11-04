package org.example.sender

import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.sealdrop.api.Sealdrop
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest

/**
 * The sending app's steps of the end-to-end check (tools/e2e/run.py). The files are made up from a seed, so the
 * harness can check what the collector stored: file i is SHA-256("seed:i:0") ‖ SHA-256("seed:i:1") ‖ …, cut to size.
 */
@RunWith(AndroidJUnit4::class)
class E2eSender {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val args = InstrumentationRegistry.getArguments()
    private val context = instrumentation.targetContext

    private fun arg(name: String, default: String? = null): String = args.getString(name) ?: default ?: error("missing $name")
    private fun report(vararg values: Pair<String, Any?>) =
        instrumentation.sendStatus(2, Bundle().apply { for ((k, v) in values) putString(k, v.toString()) })

    private fun e2e() = assumeTrue("only for tools/e2e", args.getString("e2e") == "1")

    private fun madeUp(seed: String, index: Int, size: Long, into: File) {
        into.outputStream().buffered(1 shl 20).use { out ->
            var left = size
            var k = 0
            while (left > 0) {
                val block = MessageDigest.getInstance("SHA-256").digest("$seed:$index:$k".toByteArray())
                out.write(block, 0, minOf(left, 32L).toInt())
                left -= 32
                k++
            }
        }
    }

    @Test
    fun handOver() {
        e2e()
        val delivery = arg("delivery")
        val count = arg("files", "1").toInt()
        val size = arg("size", "1000").toLong()
        val seed = arg("seed", delivery)
        val folder = File(context.cacheDir, "e2e").apply { deleteRecursively(); mkdirs() }
        val files = (0 until count).map { i -> "e2e/f$i.bin" to File(folder, "f$i.bin").also { madeUp(seed, i, size, it) } }
        val code = Sender(context).use { it.handOver(delivery, files, arg("network", "1").toInt()) }
        folder.deleteRecursively()
        report("code" to code)
        args.getString("expect")?.let { assertEquals("hand-over result", it.toInt(), code) }
    }

    @Test
    fun state() {
        e2e()
        val ids = arg("deliveries").split(",")
        val states = Sender(context).use { it.connect()!!.status(ids.toTypedArray()) }
        report("states" to states.joinToString(" ") { "${it.delivery}:${it.state}" })
        args.getString("expect")?.let { expected ->
            assertEquals(expected, states.joinToString(",") { it.state.toString() })
        }
    }

    @Test
    fun info() {
        e2e()
        val info = Sender(context).use { it.connect()!!.info() }
        report("paired" to info.paired, "warnings" to info.warnings, "waiting" to info.waiting, "lost_at" to info.lostAt,
            "max" to info.maxDeliveryBytes)
    }

    @Test
    fun sendNow() {
        e2e()
        assertEquals(Sealdrop.OK, Sender(context).use { it.connect()!!.sendNow(false) })
    }
}

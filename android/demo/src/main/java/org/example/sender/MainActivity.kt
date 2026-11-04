package org.example.sender

import android.app.Activity
import android.os.Bundle
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import app.sealdrop.api.Sealdrop
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread

/** Three buttons: hand over a small made-up file, ask for the states, and send now. */
class MainActivity : Activity() {
    private lateinit var log: TextView
    private val sender by lazy { Sender(applicationContext) }
    private val handed = ArrayList<String>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        log = TextView(this).apply { setPadding(0, 32, 0, 0) }
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 96, 48, 48)
            addView(TextView(this@MainActivity).apply {
                text = "Example Sender hands made-up files to Sealdrop."
                textSize = 18f
            })
            addView(button("Hand over a test file") { handOver() })
            addView(button("Check their states") { check() })
            addView(button("Send now") { say("sendNow: " + (sender.connect()?.sendNow(false) ?: "no Sealdrop")) })
            addView(log)
        }
        setContentView(ScrollView(this).apply { addView(column) })
    }

    private fun button(label: String, action: () -> Unit) = Button(this).apply {
        text = label
        isAllCaps = false
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        setOnClickListener { thread { action() } }
    }

    private fun say(text: String) = runOnUiThread { log.append(text + "\n") }

    private fun handOver() {
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.ROOT).format(Date())
        val file = File(filesDir, "note-$stamp.txt").apply { writeText("A made-up note, written at $stamp.\n") }
        val delivery = "note-$stamp"
        val code = sender.handOver(delivery, listOf("notes/${file.name}" to file))
        if (code == Sealdrop.OK || code == Sealdrop.ALREADY_HAVE) handed += delivery
        say("$delivery: " + when (code) {
            Sealdrop.OK -> "handed over"
            Sealdrop.NOT_APPROVED -> "not approved yet: open Sealdrop and approve this app"
            Sealdrop.NOT_PAIRED -> "Sealdrop isn't paired"
            -1 -> "Sealdrop isn't installed"
            else -> "result $code"
        })
    }

    private fun check() {
        val states = sender.connect()?.status(handed.toTypedArray()) ?: return say("no Sealdrop, or not approved")
        if (states.isEmpty()) say("nothing handed over yet")
        for (s in states) say("${s.delivery}: ${Sender.stateName(s.state)}")
    }

    override fun onDestroy() {
        sender.close()
        super.onDestroy()
    }
}

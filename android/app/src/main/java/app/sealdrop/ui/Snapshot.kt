package app.sealdrop.ui

import android.content.pm.PackageManager
import androidx.compose.ui.graphics.asImageBitmap
import androidx.core.graphics.drawable.toBitmap
import app.sealdrop.Engine
import app.sealdrop.api.Sealdrop
import app.sealdrop.net.Gate
import app.sealdrop.send.Approvals
import app.sealdrop.send.Holds
import app.sealdrop.send.Inbox
import app.sealdrop.send.Outbox
import app.sealdrop.send.Sync
import app.sealdrop.send.Warnings

/** What the screens show, read from Sealdrop's state off the main thread. */
class Snapshot(
    val paired: Boolean,
    val pending: String?,
    val status: StatusUi?,
    val request: Pair<AppUi, Approvals.Request>?,
) {
    companion object {
        fun of(engine: Engine): Snapshot {
            val paired = engine.paired()
            val pending = engine.pending()?.paired?.fingerprint
            val request = Approvals.pending(engine).firstOrNull()?.let { app(engine, it.app) to it }
            return Snapshot(paired != null, pending, paired?.let { status(engine, it) }, request)
        }

        fun app(engine: Engine, pkg: String, note: String = ""): AppUi {
            val pm = engine.context.packageManager
            return try {
                val info = pm.getApplicationInfo(pkg, 0)
                AppUi(info.loadLabel(pm).toString(), pkg, note, info.loadIcon(pm).toBitmap(96, 96).asImageBitmap())
            } catch (e: PackageManager.NameNotFoundException) {
                AppUi(pkg, pkg, note)
            }
        }

        private fun status(engine: Engine, paired: Engine.Paired): StatusUi {
            val db = engine.db
            val now = engine.clock()
            val wifiOnly = db.get(Sync.WIFI_ONLY) != null
            val net = Sync.network(engine.context, wifiOnly)
            val labels = HashMap<String, String>()
            fun label(pkg: String) = labels.getOrPut(pkg) { app(engine, pkg).name }

            val lastUpload = db.getLong(Outbox.LAST_UPLOAD).takeIf { it > 0 }?.let { at ->
                val (count, bytes) = (db.get(Outbox.LAST_UPLOAD_WHAT) ?: "0 0").split(" ").map(String::toLong)
                "${Texts.day(at, now)} · ${deliveries(count)}, ${Texts.size(bytes)}"
            }
            val waiting = db.query("SELECT COUNT(*), IFNULL(SUM(bytes), 0) FROM deliveries WHERE state BETWEEN 1 AND 3") {
                it.getLong(0) to it.getLong(1)
            }.first()
            val forWifi = if (net == Sync.Net.WIFI) 0 else
                db.long("SELECT COUNT(*) FROM deliveries WHERE state = 1 AND (network = 2 AND mobile_once = 0 OR ? = 1)", if (wifiOnly) 1 else 0)
            val onPhone = if (waiting.first == 0L) null else buildString {
                append(deliveries(waiting.first)).append(", ").append(Texts.size(waiting.second))
                if (forWifi > 0) append(" · $forWifi ").append(if (forWifi == 1L) "waits" else "wait").append(" for Wi-Fi")
            }
            val network = when (net) {
                Sync.Net.WIFI -> "Wi-Fi"
                Sync.Net.MOBILE -> "Mobile data: small items only"
                Sync.Net.NONE -> if (wifiOnly) "Waiting for Wi-Fi (Wi-Fi only is on)" else "Not connected"
            }

            val bits = Warnings.bits(engine, null)
            val warnings = ArrayList<WarningUi>()
            fun on(bit: Int) = bits and bit != 0
            if (on(Sealdrop.WARNING_STORAGE_CAP)) warnings += WarningUi(WarningKind.STORAGE_LIMIT)
            if (on(Sealdrop.WARNING_KEY_REFUSED)) warnings += WarningUi(WarningKind.KEY_REFUSED)
            if (on(Sealdrop.WARNING_NOT_PAIRED)) warnings += WarningUi(WarningKind.PAIR_AGAIN)
            if (on(Sealdrop.WARNING_CLOCK)) warnings += WarningUi(WarningKind.CLOCK)
            if (on(Sealdrop.WARNING_CANT_READ_RECEIPTS)) warnings += WarningUi(WarningKind.CANT_READ_RECEIPTS)
            if (on(Sealdrop.WARNING_TWO_COLLECTORS)) warnings += WarningUi(WarningKind.TWO_COLLECTORS)
            if (on(Sealdrop.WARNING_COLLECTOR_PROBLEM)) {
                warnings += WarningUi(WarningKind.SERVER_PROBLEM, (db.get(Inbox.COLLECTOR_WARNINGS) ?: "").split(",").joinToString(" ") {
                    when (it) {
                        "disk-full" -> "Its disk is full."
                        "inbox-flooded" -> "Its inbox is flooded with files it can't use."
                        "conflict" -> "It got a delivery that clashes with one it already has."
                        "storage-cap" -> "The storage account's limit stops its pickups."
                        else -> ""
                    }
                }.trim())
            }
            if (on(Sealdrop.WARNING_WAITING)) {
                val oldest = db.long("SELECT IFNULL(MIN(inbox_at), 0) FROM deliveries WHERE state = 3")
                warnings += WarningUi(WarningKind.WAITING, Texts.duration(now - oldest))
            }
            if (on(Sealdrop.WARNING_REJECTED)) {
                val n = db.getLong(Inbox.REJECTED_N)
                warnings += WarningUi(WarningKind.REJECTED, if (n == 1L) "one item" else "$n items")
            }
            if (on(Sealdrop.WARNING_LOST)) warnings += WarningUi(WarningKind.LOST)
            if (on(Sealdrop.WARNING_HELD_LONG)) warnings += WarningUi(WarningKind.HELD_LONG)
            if (on(Sealdrop.WARNING_FAILED)) warnings += WarningUi(WarningKind.FAILED)

            val holds = Holds.active(engine).map { HoldUi(label(it.app), Texts.clock(it.since), it.app) }
            val failed = db.query("SELECT app, delivery, bytes, time, reason FROM deliveries WHERE state = 6 AND folder IS NOT NULL ORDER BY time") {
                FailedUi(label(it.getString(0)), Texts.size(it.getLong(2)), "since " + Texts.day(it.getLong(3), now).removePrefix("on "),
                    reason(it.getString(4)), it.getString(0) to it.getString(1))
            }
            val apps = Approvals.apps(engine).map { pkg ->
                val last = db.long("SELECT IFNULL(MAX(created), 0) FROM deliveries WHERE app = ?", pkg)
                app(engine, pkg, if (last == 0L) "Approved · nothing handed over yet" else "Approved · last delivery ${Texts.day(last, now)}")
            }
            return StatusUi(
                fingerprint = paired.fingerprint.replace(" ", ""),
                label = paired.label,
                storageHost = Gate.hostOf(paired.up.endpoint).name,
                lastUpload = lastUpload,
                lastPickup = db.getLong(Inbox.LAST_PICKUP).takeIf { it > 0 }?.let { Texts.ago(it, now) },
                lastBackup = db.getLong(Inbox.LAST_BACKUP).takeIf { it > 0 }?.let { Texts.day(it, now) },
                onPhone = onPhone,
                network = network,
                warnings = warnings,
                holds = holds,
                failed = failed,
                apps = apps,
                wifiOnly = wifiOnly,
            )
        }

        private fun deliveries(n: Long) = if (n == 1L) "1 delivery" else "$n deliveries"

        private fun reason(reason: String?) = when (reason) {
            "bad-file" -> "a file's checksum didn't match"
            "bad-name" -> "a file or delivery name isn't allowed"
            "no-files" -> "it has no files"
            "damaged" -> "it arrived damaged"
            "bad-signature" -> "its signature didn't check out"
            "bad-content" -> "its list of files couldn't be read"
            "too-big" -> "it's bigger than your server takes"
            else -> "your server refused it"
        }
    }
}

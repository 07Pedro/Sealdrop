package org.example.sender

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.ParcelFileDescriptor
import app.sealdrop.api.FileOffer
import app.sealdrop.api.ISealdrop
import app.sealdrop.api.Sealdrop
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * How an app hands files to Sealdrop (docs/PROTOCOL.md §9.1): bind, `begin`, `add` the open files, `commit`, then ask
 * `status` until the delivery is picked up. Call it from a background thread: binding waits for the main thread.
 */
class Sender(private val context: Context) : AutoCloseable {
    private val bound = CountDownLatch(1)
    @Volatile private var service: ISealdrop? = null

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            service = ISealdrop.Stub.asInterface(binder)
            bound.countDown()
        }

        override fun onServiceDisconnected(name: ComponentName) {
            service = null
        }
    }

    /** The interface, or null if Sealdrop isn't installed or didn't answer within 10 seconds. */
    fun connect(): ISealdrop? {
        service?.let { return it }
        val intent = Intent(Sealdrop.ACTION_DELIVER).setPackage(Sealdrop.PACKAGE)
        if (!context.bindService(intent, connection, Context.BIND_AUTO_CREATE)) return null
        bound.await(10, TimeUnit.SECONDS)
        return service
    }

    /** Hands [files] over as one delivery; the result code of the step that failed, or of `commit`. */
    fun handOver(delivery: String, files: List<Pair<String, File>>, network: Int = Sealdrop.NETWORK_MOBILE): Int {
        val sealdrop = connect() ?: return -1
        val begun = sealdrop.begin(delivery, network)
        if (begun.code != Sealdrop.OK) return begun.code
        for (chunk in files.chunked(Sealdrop.MAX_FILES_PER_ADD)) {
            val offers = chunk.map { (path, file) ->
                FileOffer().apply {
                    this.path = path
                    size = file.length()
                    sha256 = sha256(file)
                    this.file = ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
                }
            }
            val added = try {
                sealdrop.add(begun.handle, offers.toTypedArray())
            } finally {
                offers.forEach { it.file.close() }
            }
            if (added.code != Sealdrop.OK) {
                sealdrop.abort(begun.handle)
                return added.code
            }
        }
        return sealdrop.commit(begun.handle)
    }

    override fun close() {
        if (service != null) context.unbindService(connection)
        service = null
    }

    companion object {
        fun sha256(file: File): String {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(1 shl 16)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    digest.update(buffer, 0, n)
                }
            }
            return digest.digest().joinToString("") { "%02x".format(it) }
        }

        fun stateName(state: Int) = when (state) {
            Sealdrop.STATE_UNKNOWN -> "unknown"
            Sealdrop.STATE_QUEUED -> "queued"
            Sealdrop.STATE_UPLOADING -> "uploading"
            Sealdrop.STATE_IN_INBOX -> "in the inbox"
            Sealdrop.STATE_PICKED_UP -> "picked up"
            Sealdrop.STATE_CONFLICT -> "conflict"
            Sealdrop.STATE_FAILED -> "failed"
            else -> "state $state"
        }
    }
}

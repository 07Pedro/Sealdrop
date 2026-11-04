package app.sealdrop.send

import android.content.pm.PackageManager
import app.sealdrop.Engine
import app.sealdrop.Notes
import app.sealdrop.core.Encoding

/**
 * Which apps may hand files over (PROTOCOL.md §9.1): by package name and the SHA-256 of their signing certificate.
 * An unapproved app's first call becomes a request, shown once; a refused or withdrawn app isn't asked about again
 * for [QUIET_MS], so it can't nag.
 */
object Approvals {
    const val QUIET_MS = 30 * 86_400_000L

    class Request(val app: String, val cert: String, val at: Long)

    /** The caller's package, if Android gives exactly one for [uid] and the owner approved it with this certificate. */
    fun approved(engine: Engine, uid: Int): String? {
        val pm = engine.context.packageManager
        val packages = pm.getPackagesForUid(uid) ?: return null
        if (packages.size != 1) return null
        val app = packages[0]
        val cert = engine.db.string("SELECT cert FROM approvals WHERE app = ?", app)
        if (cert != null && pm.hasSigningCertificate(uid, Encoding.unhex(cert), PackageManager.CERT_INPUT_SHA256)) return app
        noteRequest(engine, app)
        return null
    }

    /** The certificate an app is signed with now, hex; null if it has several signers (refused). */
    fun certificateOf(engine: Engine, app: String): String? {
        val info = try {
            engine.context.packageManager.getPackageInfo(app, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo
        } catch (e: PackageManager.NameNotFoundException) {
            null
        } ?: return null
        if (info.hasMultipleSigners()) return null
        val cert = info.apkContentsSigners.singleOrNull() ?: return null
        return Encoding.hex(Encoding.sha256(cert.toByteArray()))
    }

    private fun noteRequest(engine: Engine, app: String) {
        val cert = certificateOf(engine, app) ?: return
        val db = engine.db
        val now = engine.clock()
        val known = db.query("SELECT cert, refused FROM requests WHERE app = ?", app) { it.getString(0) to it.getLong(1) }
            .firstOrNull()
        if (known != null && known.first == cert && (known.second == 0L || now - known.second < QUIET_MS)) return
        db.exec("INSERT OR REPLACE INTO requests (app, cert, at, refused) VALUES (?, ?, ?, 0)", app, cert, now)
        Engine.log("approval requested")
        Notes.request(engine.context)
        engine.changed()
    }

    /** Requests the owner hasn't answered yet, oldest first. */
    fun pending(engine: Engine): List<Request> =
        engine.db.query("SELECT app, cert, at FROM requests WHERE refused = 0 ORDER BY at") {
            Request(it.getString(0), it.getString(1), it.getLong(2))
        }

    fun approve(engine: Engine, request: Request) {
        engine.db.tx {
            engine.db.exec("INSERT OR REPLACE INTO approvals (app, cert, at) VALUES (?, ?, ?)", request.app, request.cert, engine.clock())
            engine.db.exec("DELETE FROM requests WHERE app = ?", request.app)
        }
        Notes.cancelRequest(engine.context)
        engine.changed()
    }

    fun refuse(engine: Engine, request: Request) {
        engine.db.exec("UPDATE requests SET refused = ? WHERE app = ?", engine.clock(), request.app)
        if (pending(engine).isEmpty()) Notes.cancelRequest(engine.context)
        engine.changed()
    }

    /** Withdrawing an approval: the app's calls are refused from now on; what it handed over is still sent. */
    fun withdraw(engine: Engine, app: String) {
        engine.db.tx {
            val cert = engine.db.string("SELECT cert FROM approvals WHERE app = ?", app) ?: ""
            engine.db.exec("DELETE FROM approvals WHERE app = ?", app)
            engine.db.exec("DELETE FROM holds WHERE app = ?", app)
            engine.db.exec("INSERT OR REPLACE INTO requests (app, cert, at, refused) VALUES (?, ?, ?, ?)",
                app, cert, engine.clock(), engine.clock())
        }
        engine.changed()
    }

    fun apps(engine: Engine): List<String> = engine.db.query("SELECT app FROM approvals ORDER BY at") { it.getString(0) }
}

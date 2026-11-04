package app.sealdrop.data

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * What Sealdrop keeps (PROTOCOL.md §9.4), in its private, credential-encrypted storage: approvals, holds, the
 * deliveries and their files, the sealed uploads still pending, the `seq` of picked-up deliveries, the receipts
 * handled, and small values. Secrets are not here: they're in [Vault].
 */
class Db(context: Context, name: String = "sealdrop.db") : SQLiteOpenHelper(context, name, null, 1) {
    override fun onConfigure(db: SQLiteDatabase) {
        db.enableWriteAheadLogging()
    }

    override fun onCreate(db: SQLiteDatabase) {
        for (statement in SCHEMA.split(";").map { it.trim() }.filter { it.isNotEmpty() }) db.execSQL(statement)
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit

    val db: SQLiteDatabase get() = writableDatabase

    fun <T> tx(block: (SQLiteDatabase) -> T): T {
        val d = db
        d.beginTransaction()
        try {
            val result = block(d)
            d.setTransactionSuccessful()
            return result
        } finally {
            d.endTransaction()
        }
    }

    // --- small values -----------------------------------------------------------------------------------------------

    fun get(key: String): String? = db.rawQuery("SELECT v FROM kv WHERE k = ?", arrayOf(key)).use { c ->
        if (c.moveToFirst()) c.getString(0) else null
    }

    fun put(key: String, value: String?) {
        if (value == null) db.delete("kv", "k = ?", arrayOf(key))
        else db.insertWithOnConflict("kv", null, values("k" to key, "v" to value), SQLiteDatabase.CONFLICT_REPLACE)
    }

    fun getLong(key: String, default: Long = 0): Long = get(key)?.toLongOrNull() ?: default
    fun putLong(key: String, value: Long) = put(key, value.toString())

    // --- helpers ----------------------------------------------------------------------------------------------------

    fun <T> query(sql: String, vararg args: Any?, row: (Cursor) -> T): List<T> =
        db.rawQuery(sql, args.map { it?.toString() }.toTypedArray()).use { c ->
            buildList { while (c.moveToNext()) add(row(c)) }
        }

    fun long(sql: String, vararg args: Any?): Long =
        db.rawQuery(sql, args.map { it?.toString() }.toTypedArray()).use { c -> if (c.moveToFirst()) c.getLong(0) else 0 }

    fun exec(sql: String, vararg args: Any?) = db.execSQL(sql, args)

    fun string(sql: String, vararg args: Any?): String? =
        db.rawQuery(sql, args.map { it?.toString() }.toTypedArray()).use { c ->
            if (c.moveToFirst() && !c.isNull(0)) c.getString(0) else null
        }

    companion object {
        fun values(vararg pairs: Pair<String, Any?>) = ContentValues().apply {
            for ((k, v) in pairs) when (v) {
                null -> putNull(k)
                is String -> put(k, v)
                is Int -> put(k, v)
                is Long -> put(k, v)
                is Boolean -> put(k, if (v) 1 else 0)
                else -> error("unsupported value for $k")
            }
        }

        private const val SCHEMA = """
CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE approvals (app TEXT PRIMARY KEY, cert TEXT NOT NULL, at INTEGER NOT NULL);
CREATE TABLE requests (app TEXT PRIMARY KEY, cert TEXT NOT NULL, at INTEGER NOT NULL, refused INTEGER NOT NULL DEFAULT 0);
CREATE TABLE holds (app TEXT PRIMARY KEY, since INTEGER NOT NULL, until INTEGER NOT NULL);
CREATE TABLE deliveries (
    app TEXT NOT NULL, delivery TEXT NOT NULL, digest TEXT NOT NULL, network INTEGER NOT NULL,
    state INTEGER NOT NULL, time INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, bytes INTEGER NOT NULL,
    files INTEGER NOT NULL, folder TEXT, strikes INTEGER NOT NULL DEFAULT 0, whole_rejects INTEGER NOT NULL DEFAULT 0,
    alone INTEGER NOT NULL DEFAULT 0, mobile_once INTEGER NOT NULL DEFAULT 0, queued_at INTEGER NOT NULL,
    inbox_at INTEGER NOT NULL DEFAULT 0, final_at INTEGER NOT NULL DEFAULT 0, upload TEXT, seq INTEGER,
    key_id TEXT, reason TEXT,
    PRIMARY KEY (app, delivery));
CREATE TABLE files (
    app TEXT NOT NULL, delivery TEXT NOT NULL, idx INTEGER NOT NULL, path TEXT NOT NULL, size INTEGER NOT NULL,
    sha256 TEXT NOT NULL, PRIMARY KEY (app, delivery, idx));
CREATE TABLE uploads (
    name TEXT PRIMARY KEY, size INTEGER NOT NULL, sha256 TEXT NOT NULL, message TEXT NOT NULL, key_id TEXT NOT NULL,
    state INTEGER NOT NULL, upload_id TEXT, etags TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL,
    uploaded_at INTEGER NOT NULL DEFAULT 0, mobile INTEGER NOT NULL DEFAULT 0, rejected INTEGER NOT NULL DEFAULT 0);
CREATE INDEX uploads_sha ON uploads (sha256);
CREATE TABLE upload_deliveries (
    name TEXT NOT NULL, app TEXT NOT NULL, delivery TEXT NOT NULL, digest TEXT NOT NULL,
    counted INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (name, app, delivery));
CREATE TABLE seqs (
    key_id TEXT NOT NULL, seq INTEGER NOT NULL, app TEXT NOT NULL, delivery TEXT NOT NULL, at INTEGER NOT NULL,
    PRIMARY KEY (key_id, seq));
CREATE TABLE receipts (name TEXT PRIMARY KEY, outcome TEXT NOT NULL, at INTEGER NOT NULL);
CREATE TABLE instances (time INTEGER NOT NULL, instance TEXT NOT NULL);
CREATE TABLE lost (app TEXT PRIMARY KEY, at INTEGER NOT NULL)
"""
    }
}

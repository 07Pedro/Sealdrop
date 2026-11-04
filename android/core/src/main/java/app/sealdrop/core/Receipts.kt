package app.sealdrop.core

/**
 * Receipts (PROTOCOL.md §6), as the phone reads them once [Reading.openReceipt] has checked the file. Every field the
 * phone acts on is checked for its form here; a receipt that fails is "can't read receipts" (§6, step 3), never
 * partly used. Unknown fields are ignored.
 */
object Receipts {
    val RESULTS = setOf("stored", "duplicate", "conflict", "rejected")

    sealed interface Receipt {
        /** The phone's key ID it was written for. */
        val forKeyId: ByteArray
        val time: Long
    }

    /** The answer to a pairing request (§7). */
    class Paired(override val forKeyId: ByteArray, override val time: Long, val pairing: ByteArray) : Receipt

    /** What was stored and rejected, and the collector's status. */
    class Report(
        override val forKeyId: ByteArray,
        override val time: Long,
        val stored: List<StoredUpload>,
        val rejected: List<RejectedUpload>,
        val status: Status,
    ) : Receipt

    class StoredUpload(val message: ByteArray, val sealedSha256: String, val received: Long, val deliveries: List<DeliveryResult>)

    /** [seq] only for `stored`, and for `duplicate` first stored for this sender; [reason] only for `rejected`. */
    class DeliveryResult(
        val app: String, val delivery: String, val digest: String, val result: String, val seq: Long?, val reason: String?,
    )

    /** [sealedSha256] only if the collector downloaded the file. */
    class RejectedUpload(val name: String, val sealedSha256: String?, val size: Long, val reason: String, val at: Long)

    /** [lastPickup] and [lastBackup] are null until there was one. */
    class Status(
        val collector: String,
        val instance: ByteArray,
        val seq: Long,
        val lastPickup: Long?,
        val lastBackup: Long?,
        val freeBytes: Long,
        val maxSealed: Long,
        val warnings: List<String>,
        val rejected7d: Long,
        val rejectedMore: Long,
        val vanished7d: Long,
    )

    /** The receipt in [manifest], if its form is right and it's for one of [ownKeyIds]; FormatException otherwise. */
    fun parse(manifest: Any?, ownKeyIds: List<ByteArray>): Receipt {
        val m = manifest as? Map<*, *> ?: throw FormatException("not an object")
        if (!Encoding.isOne(m["v"])) throw FormatException("v")
        val type = m["type"]
        if (type != "receipt" && type != "paired") throw FormatException("type")
        val forKeyId = Encoding.unhex(m["for"], 32)
        if (ownKeyIds.none { it.contentEquals(forKeyId) }) throw FormatException("for")
        val time = int(m, "time")
        if (type == "paired") return Paired(forKeyId, time, Encoding.unb64url(m["pairing"], 16))
        return Report(
            forKeyId, time,
            stored = list(m, "stored").map(::storedUpload),
            rejected = list(m, "rejected").map(::rejectedUpload),
            status = status(m["status"] as? Map<*, *> ?: throw FormatException("status")),
        )
    }

    private fun storedUpload(item: Any?): StoredUpload {
        val e = item as? Map<*, *> ?: throw FormatException("stored entry")
        return StoredUpload(
            message = Encoding.unhex(e["message"], 16),
            sealedSha256 = sha256(e["sealed_sha256"]),
            received = int(e, "received"),
            deliveries = list(e, "deliveries").map { d ->
                d as? Map<*, *> ?: throw FormatException("delivery entry")
                val result = d["result"] as? String ?: throw FormatException("result")
                if (result !in RESULTS) throw FormatException("result")
                DeliveryResult(
                    app = string(d, "app"),
                    delivery = string(d, "delivery"),
                    digest = sha256(d["digest"]),
                    result = result,
                    seq = if ("seq" in d) int(d, "seq") else null,
                    reason = if (result == "rejected") string(d, "reason") else null,
                )
            },
        )
    }

    private fun rejectedUpload(item: Any?): RejectedUpload {
        val e = item as? Map<*, *> ?: throw FormatException("rejected entry")
        return RejectedUpload(
            name = string(e, "name"),
            sealedSha256 = if ("sealed_sha256" in e) sha256(e["sealed_sha256"]) else null,
            size = int(e, "size"),
            reason = string(e, "reason"),
            at = int(e, "at"),
        )
    }

    private fun status(s: Map<*, *>) = Status(
        collector = string(s, "collector"),
        instance = Encoding.unhex(s["instance"], 16),
        seq = int(s, "seq"),
        lastPickup = intOrNull(s, "last_pickup"),
        lastBackup = intOrNull(s, "last_backup"),
        freeBytes = int(s, "free_bytes"),
        maxSealed = int(s, "max_sealed"),
        warnings = list(s, "warnings").map { it as? String ?: throw FormatException("warnings") },
        rejected7d = int(s, "rejected_7d"),
        rejectedMore = int(s, "rejected_more"),
        vanished7d = int(s, "vanished_7d"),
    )

    private fun int(m: Map<*, *>, name: String): Long = m[name] as? Long ?: throw FormatException(name)

    private fun intOrNull(m: Map<*, *>, name: String): Long? {
        if (name !in m) throw FormatException(name)
        return m[name]?.let { it as? Long ?: throw FormatException(name) }
    }

    private fun string(m: Map<*, *>, name: String): String = m[name] as? String ?: throw FormatException(name)

    private fun list(m: Map<*, *>, name: String): List<*> = m[name] as? List<*> ?: throw FormatException(name)

    private fun sha256(value: Any?): String = Encoding.hex(Encoding.unhex(value, 32))
}

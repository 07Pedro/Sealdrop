package app.sealdrop.core

import java.nio.ByteBuffer

class FileEntry(val path: String, val size: Long, val sha256: String)

class Delivery(
    val app: String,
    val delivery: String,
    val created: Long,
    val files: List<FileEntry>,
    /** A per-delivery reason found in the manifest ([Reasons.BAD_NAME], [Reasons.NO_FILES], [Reasons.BAD_FILE]). */
    val problem: String? = null,
) {
    val digest: String = Manifests.deliveryDigest(files)
    val size: Long get() = files.sumOf { it.size }
}

class PairRequest(
    val pairing: ByteArray,
    val senderSign: ByteArray,
    val senderOpen: ByteArray,
    val label: String,
    val replaces: ByteArray?,
    val mac: ByteArray,
)

/** The content of a sealed file and its manifests (PROTOCOL.md §5, §7). */
object Manifests {
    const val MAX_DELIVERIES = 1000
    const val MAX_FILES = 10_000
    const val MAX_NAME = 100
    const val MAX_PATH_BYTES = 255
    const val MAX_PARTS = 8
    const val MAX_PART = 128
    const val MAX_LABEL = 40

    private val APP = Regex("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+")
    private val PART = Regex("[A-Za-z0-9][A-Za-z0-9._-]*")
    private val SHA256 = Regex("[0-9a-f]{64}")
    private val RESERVED = setOf("con", "prn", "aux", "nul") + (0..9).map { "com$it" } + (0..9).map { "lpt$it" }

    // --- content = manifest length ‖ manifest ‖ files ---------------------------------------------------------------

    fun contentPrefix(manifest: Map<String, Any?>): ByteArray {
        val raw = Json.write(manifest)
        return ByteBuffer.allocate(4).putInt(raw.size).array() + raw
    }

    /** (manifest, the bytes after it) for content in memory; [Rejected] (`bad-content`) if it can't be read. */
    fun splitContent(content: ByteArray, kind: Int): Pair<Any?, ByteArray> {
        if (content.size < 4) throw Rejected(Reasons.BAD_CONTENT, "no manifest length")
        val m = ByteBuffer.wrap(content, 0, 4).getInt().toLong() and 0xFFFFFFFFL
        val limit = if (kind == Sizes.KIND_BUNDLE) Sizes.MANIFEST_ROOM else Sizes.SMALL_MAX.toLong()
        if (m > limit || 4 + m > content.size) throw Rejected(Reasons.BAD_CONTENT, "manifest length")
        if (kind != Sizes.KIND_BUNDLE && 4 + m != content.size.toLong()) {
            throw Rejected(Reasons.BAD_CONTENT, "bytes after the manifest")
        }
        val manifest = try {
            Json.parse(content.copyOfRange(4, 4 + m.toInt()))
        } catch (e: FormatException) {
            throw Rejected(Reasons.BAD_CONTENT, e.message ?: "")
        }
        return manifest to content.copyOfRange(4 + m.toInt(), content.size)
    }

    // --- names --------------------------------------------------------------------------------------------------

    /** ASCII case folding: A–Z to a–z and nothing else (never a language's lower-casing). */
    fun fold(text: String): String = buildString(text.length) {
        for (c in text) append(if (c in 'A'..'Z') c + 32 else c)
    }

    /** Characters as the protocol counts them: code points, not UTF-16 units. */
    private fun characters(text: String): Int = text.codePointCount(0, text.length)

    fun goodApp(app: String): Boolean = characters(app) in 1..MAX_NAME && APP.matches(app)

    private fun goodPart(part: String): Boolean =
        characters(part) in 1..MAX_PART && PART.matches(part) && !part.endsWith(".") &&
            fold(part.substringBefore('.')) !in RESERVED

    fun goodDelivery(delivery: String): Boolean = characters(delivery) <= MAX_NAME && goodPart(delivery)

    fun goodPath(path: String): Boolean {
        val parts = path.split("/")
        return path.toByteArray(Charsets.UTF_8).size <= MAX_PATH_BYTES && parts.size in 1..MAX_PARTS &&
            parts.all(::goodPart)
    }

    /** Two paths equal after folding, or one a folder of another (`a.x` sorts between `a` and `a/b`). */
    fun pathsClash(paths: List<String>): Boolean {
        val folded = paths.map(::fold)
        val known = folded.toHashSet()
        if (known.size != folded.size) return true
        return folded.any { path -> path.indices.any { i -> path[i] == '/' && path.substring(0, i) in known } }
    }

    /** 1 to 40 characters, none of them a control, format or line/paragraph separator (Cc, Cf, Zl, Zp). */
    fun goodLabel(label: Any?): Boolean {
        if (label !is String || characters(label) !in 1..MAX_LABEL) return false
        return label.codePoints().allMatch {
            when (Character.getType(it).toByte()) {
                Character.CONTROL, Character.FORMAT, Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR -> false
                else -> true
            }
        }
    }

    // --- bundles (kind 1) ------------------------------------------------------------------------------------------

    /** §5: SHA-256 over path, size and checksum of every file, sorted by path (UTF-8 byte order). */
    fun deliveryDigest(files: List<FileEntry>): String {
        val sorted = files.map { it to it.path.toByteArray(Charsets.UTF_8) }.sortedWith { a, b -> compareBytes(a.second, b.second) }
        val text = sorted.joinToString("") { (f, _) -> "${f.path}\n${f.size}\n${f.sha256}\n" }
        return Encoding.hex(Encoding.sha256(text.toByteArray(Charsets.UTF_8)))
    }

    private fun compareBytes(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return a.size - b.size
    }

    private fun envelope(condition: Boolean, detail: String) {
        if (!condition) throw Rejected(Reasons.BAD_CONTENT, detail)
    }

    /**
     * Every check of §5 that the manifest alone allows, for content of [n] bytes with an [m]-byte manifest. Throws
     * [Rejected] for an envelope failure; a delivery that breaks a name rule, has no files or has a malformed
     * checksum comes back with its `problem` set.
     */
    fun checkBundle(manifest: Any?, n: Long, m: Long): List<Delivery> {
        envelope(manifest is Map<*, *>, "not an object")
        manifest as Map<*, *>
        envelope(Encoding.isOne(manifest["v"]) && manifest["type"] == "bundle", "v or type")
        val items = manifest["deliveries"]
        envelope(items is List<*> && items.size in 1..MAX_DELIVERIES, "deliveries")
        val deliveries = ArrayList<Delivery>()
        val seen = HashSet<Pair<String, String>>()
        var totalFiles = 0
        var totalBytes = 0L
        for (item in items as List<*>) {
            envelope(item is Map<*, *>, "delivery not an object")
            item as Map<*, *>
            val app = item["app"]
            val delivery = item["delivery"]
            val created = item["created"]
            val files = item["files"]
            envelope(app is String && delivery is String, "app or delivery")
            app as String
            delivery as String
            envelope(characters(app) <= MAX_NAME && characters(delivery) <= MAX_NAME, "app or delivery too long")
            envelope(created is Long && files is List<*>, "created or files")
            envelope(seen.add(app to delivery), "the same delivery twice")
            val entries = (files as List<*>).map { f ->
                envelope(f is Map<*, *>, "file not an object")
                f as Map<*, *>
                val path = f["path"]
                val size = f["size"]
                val sha = f["sha256"]
                envelope(path is String && size is Long && sha is String, "file fields")
                totalBytes = try {
                    Math.addExact(totalBytes, size as Long)
                } catch (e: ArithmeticException) {
                    throw Rejected(Reasons.BAD_CONTENT, "file sizes don't add up")
                }
                FileEntry(path as String, size, sha as String)
            }
            totalFiles += entries.size
            envelope(totalFiles <= MAX_FILES, "more than 10,000 files")
            val problem = when {
                !goodApp(app) || !goodDelivery(delivery) || !entries.all { goodPath(it.path) } ||
                    pathsClash(entries.map { it.path }) -> Reasons.BAD_NAME
                entries.isEmpty() -> Reasons.NO_FILES
                !entries.all { SHA256.matches(it.sha256) } -> Reasons.BAD_FILE
                else -> null
            }
            deliveries.add(Delivery(app, delivery, created as Long, entries, problem))
        }
        envelope(4 + m + totalBytes == n, "file sizes don't add up")
        return deliveries
    }

    fun bundleManifest(deliveries: List<Delivery>): Map<String, Any?> = linkedMapOf(
        "v" to 1L,
        "type" to "bundle",
        "deliveries" to deliveries.map { d ->
            linkedMapOf(
                "app" to d.app, "delivery" to d.delivery, "created" to d.created,
                "files" to d.files.map { linkedMapOf("path" to it.path, "size" to it.size, "sha256" to it.sha256) },
            )
        },
    )

    // --- pairing requests (kind 2) ----------------------------------------------------------------------------------

    /** §7 step 1: the manifest's form. The label and `replaces` rules are step 6 ([checkPairNames]). */
    fun parsePair(manifest: Any?): PairRequest {
        try {
            if (manifest !is Map<*, *> || !Encoding.isOne(manifest["v"]) || manifest["type"] != "pair") {
                throw FormatException("v or type")
            }
            val label = manifest["label"] as? String ?: throw FormatException("label")
            return PairRequest(
                pairing = Encoding.unb64url(manifest["pairing"], 16),
                senderSign = Encoding.unb64url(manifest["sender_sign"], 65),
                senderOpen = Encoding.unb64url(manifest["sender_open"], 32),
                label = label,
                replaces = if ("replaces" in manifest) Encoding.unhex(manifest["replaces"], 32) else null, // never null
                mac = Encoding.unb64url(manifest["mac"], 32),
            )
        } catch (e: FormatException) {
            throw Rejected(Reasons.BAD_CONTENT, e.message ?: "")
        }
    }

    /** §7 step 6: what's wrong with the label or `replaces`, or null. */
    fun checkPairNames(request: PairRequest): String? = when {
        !goodLabel(request.label) -> "label not allowed"
        request.replaces != null && request.replaces.all { it == 0.toByte() } -> "replaces is all zeros"
        else -> null
    }

    fun pairManifest(
        pairing: ByteArray, senderSign: ByteArray, senderOpen: ByteArray, label: String, replaces: ByteArray?, mac: ByteArray,
    ): Map<String, Any?> = linkedMapOf<String, Any?>(
        "v" to 1L,
        "type" to "pair",
        "pairing" to Encoding.b64url(pairing),
        "sender_sign" to Encoding.b64url(senderSign),
        "sender_open" to Encoding.b64url(senderOpen),
        "label" to label,
    ).apply {
        if (replaces != null) put("replaces", Encoding.hex(replaces))
        put("mac", Encoding.b64url(mac))
    }
}

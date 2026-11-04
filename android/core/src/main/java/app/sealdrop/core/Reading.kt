package app.sealdrop.core

import app.sealdrop.core.Sizes.KIND_BUNDLE
import app.sealdrop.core.Sizes.KIND_PAIR
import app.sealdrop.core.Sizes.KIND_RECEIPT
import java.security.MessageDigest
import java.security.PrivateKey

class Verdict(val delivery: Delivery, val ok: Boolean, val reason: String?)

class OpenedPairRequest(val header: Header, val request: PairRequest, val manifest: Map<*, *>)

/** Takes a file's bytes as they're read; [checkDeliveries] asks for one per file of a delivery that passed. */
typealias FileSink = (Delivery, FileEntry) -> ((ByteArray, Int, Int) -> Unit)?

/**
 * Reading uploads, pairing requests and receipts in the order PROTOCOL.md §4, §5 and §7 give. The phone reads
 * receipts; the rest is the collector's side, here so both sides can be tested against the same files.
 */
object Reading {
    /** §4 steps 1 to 5 for a file in `up/`, as a regular run reads it: a pairing request is `unknown-sender`. */
    fun openUpload(
        source: SealedSource, openingKeys: List<PrivateKey>, senders: Map<String, Verifier>,
        maxSealed: Long = Sizes.DEFAULT_MAX_SEALED,
    ): SealedFile {
        Sealed.checkListedSize(Where.UP, source.size, maxSealed)
        val sealed = SealedFile(source)
        val header = sealed.openHeader(openingKeys, Sealed.INFO_TO_COLLECTOR, listOf(KIND_BUNDLE, KIND_PAIR))
        val verifier = if (header.kind == KIND_BUNDLE) senders[Encoding.hex(header.writerKeyId)] else null
        sealed.verify(verifier ?: throw Rejected(Reasons.UNKNOWN_SENDER))
        return sealed
    }

    /**
     * §4 steps 6 and 7 with §5: decrypts, reads the manifest, then every file against its size and checksum. Only
     * deliveries whose names and limits passed get a [fileSink], so a rejected delivery's bytes are checked but never
     * handed out. A whole-file failure throws [Rejected]; anything else comes back per delivery.
     */
    fun checkDeliveries(sealed: SealedFile, fileSink: FileSink? = null): List<Verdict> {
        val header = sealed.header ?: throw IllegalStateException("open the upload first")
        val stream = sealed.content()
        fun read(length: Int): ByteArray {
            val data = stream.readNBytes(length)
            if (data.size != length) throw Rejected(Reasons.BAD_CONTENT, "content ends early")
            return data
        }

        val m = java.nio.ByteBuffer.wrap(read(4)).getInt().toLong() and 0xFFFFFFFFL
        if (m > Sizes.MANIFEST_ROOM || 4 + m > header.n) throw Rejected(Reasons.BAD_CONTENT, "manifest length")
        val manifest = try {
            Json.parse(read(m.toInt()))
        } catch (e: FormatException) {
            throw Rejected(Reasons.BAD_CONTENT, e.message ?: "")
        }
        val buffer = ByteArray(Sizes.PIECE)
        return Manifests.checkBundle(manifest, header.n, m).map { delivery ->
            var ok = delivery.problem == null
            for (entry in delivery.files) {
                val digest = MessageDigest.getInstance("SHA-256")
                val sink = if (ok && fileSink != null) fileSink(delivery, entry) else null
                var left = entry.size
                while (left > 0) {
                    val got = stream.read(buffer, 0, minOf(left, buffer.size.toLong()).toInt())
                    if (got < 0) throw Rejected(Reasons.BAD_CONTENT, "content ends early")
                    digest.update(buffer, 0, got)
                    sink?.invoke(buffer, 0, got)
                    left -= got
                }
                if (Encoding.hex(digest.digest()) != entry.sha256) ok = false
            }
            Verdict(delivery, ok, delivery.problem ?: if (ok) null else Reasons.BAD_FILE)
        }.also { stream.finish() } // the padding check runs at the end of the pieces
    }

    /** §7, what the `pair` command checks before it looks for a waiting pairing (steps 1 to 4). */
    fun openPairRequest(source: SealedSource, openingKeys: List<PrivateKey>): OpenedPairRequest {
        Sealed.checkListedSize(Where.UP, source.size)
        val sealed = SealedFile(source)
        val header = sealed.openHeader(openingKeys, Sealed.INFO_TO_COLLECTOR, listOf(KIND_PAIR))
        val content = sealed.readContent(checkPadding = false) // at most 256 KiB; the padding is step 4
        val manifest = Manifests.splitContent(content, KIND_PAIR).first
        val request = Manifests.parsePair(manifest)
        if (!Keys.keyId(request.senderSign).contentEquals(header.writerKeyId)) {
            throw Rejected(Reasons.UNKNOWN_SENDER, "sender_sign doesn't match the key ID")
        }
        val verifier = try {
            P256Verifier(request.senderSign)
        } catch (e: IllegalArgumentException) {
            throw Rejected(Reasons.BAD_CONTENT, "sender_sign isn't a P-256 point")
        }
        sealed.verify(verifier)
        if (!sealed.paddingOk) throw Rejected(Reasons.DAMAGED, "padding isn't zero")
        return OpenedPairRequest(header, request, manifest as Map<*, *>)
    }

    /**
     * The phone's side (§6, steps 1 to 3): size, header, writer, signature, content. The manifest's form is checked by
     * [Receipts.parse].
     */
    fun openReceipt(
        data: ByteArray, openingKeys: List<PrivateKey>, collector: Verifier, collectorKeyId: ByteArray,
    ): Pair<Header, Any?> {
        Sealed.checkListedSize(Where.ACK, data.size.toLong())
        val sealed = SealedFile(BytesSource(data))
        val header = sealed.openHeader(openingKeys, Sealed.INFO_TO_SENDER, listOf(KIND_RECEIPT))
        if (!header.writerKeyId.contentEquals(collectorKeyId)) throw Rejected(Reasons.UNKNOWN_SENDER)
        sealed.verify(collector)
        return header to Manifests.splitContent(sealed.readContent(), KIND_RECEIPT).first
    }
}

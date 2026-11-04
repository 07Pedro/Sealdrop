package app.sealdrop.core

import app.sealdrop.core.Sizes.KIND_RECEIPT
import app.sealdrop.core.Sizes.PIECE
import app.sealdrop.core.Sizes.PREFIX
import app.sealdrop.core.Sizes.SIGNATURE
import app.sealdrop.core.Sizes.TAG
import java.io.Closeable
import java.io.EOFException
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** The 104-byte header inside a sealed file (PROTOCOL.md §4). */
class Header(
    val kind: Int,
    /** The writer's clock: only shown, never trusted. */
    val created: Long,
    /** The content length `n`. */
    val n: Long,
    val messageId: ByteArray,
    val writerKeyId: ByteArray,
    val fileKey: ByteArray,
) {
    init {
        require(messageId.size == 16 && writerKeyId.size == 32 && fileKey.size == 32)
    }

    val length: Long get() = Sizes.paddedLength(kind, n)
    val pieces: Long get() = Sizes.pieces(length)
    val sealedSize: Long get() = Sizes.sealedSize(length)

    fun pack(): ByteArray = ByteBuffer.allocate(Sealed.HEADER_LEN)
        .put(Sealed.VERSION.toByte()).put(kind.toByte()).putShort(0).putInt(PIECE).putLong(created).putLong(n)
        .put(messageId).put(writerKeyId).put(fileKey)
        .array()

    companion object {
        fun unpack(raw: ByteArray, expectedKinds: Collection<Int>): Header {
            val b = ByteBuffer.wrap(raw)
            val version = b.get().toInt() and 0xFF
            val kind = b.get().toInt() and 0xFF
            val reserved = b.getShort().toInt()
            val piece = b.getInt()
            val created = b.getLong()
            val n = b.getLong()
            val messageId = ByteArray(16).also { b.get(it) }
            val writer = ByteArray(32).also { b.get(it) }
            val key = ByteArray(32).also { b.get(it) }
            if (version != Sealed.VERSION || kind !in expectedKinds || reserved != 0 || piece != PIECE) {
                throw Rejected(Reasons.DAMAGED, "header fields")
            }
            val header = Header(kind, created, n, messageId, writer, key)
            try {
                header.length // n is unsigned: a negative Long here is above 2^63, too big for any kind
            } catch (e: IllegalArgumentException) {
                throw Rejected(Reasons.DAMAGED, "content length too big for the kind")
            }
            return header
        }
    }
}

/** [sha256]: of the whole file, hex (a receipt's `sealed_sha256`). */
class SealResult(val header: Header, val size: Long, val sha256: String)

/** Where a sealed file is read from: random access, because the header and the signature come first (§4). */
interface SealedSource {
    val size: Long

    /** Exactly [length] bytes at [offset], or fewer at the end. */
    fun readAt(offset: Long, length: Int): ByteArray
}

class BytesSource(private val data: ByteArray) : SealedSource {
    override val size: Long get() = data.size.toLong()

    override fun readAt(offset: Long, length: Int): ByteArray {
        if (offset >= data.size) return ByteArray(0)
        return data.copyOfRange(offset.toInt(), minOf(data.size.toLong(), offset + length).toInt())
    }
}

class FileSource(file: File) : SealedSource, Closeable {
    private val raf = RandomAccessFile(file, "r")
    override val size: Long = raf.length()

    override fun readAt(offset: Long, length: Int): ByteArray {
        raf.seek(offset)
        val out = ByteArray(minOf(length.toLong(), maxOf(0, size - offset)).toInt())
        raf.readFully(out)
        return out
    }

    override fun close() = raf.close()
}

/** The sealed file (PROTOCOL.md §4): writing it, and reading it in the order §4 gives. */
object Sealed {
    const val VERSION = 1
    const val HEADER_LEN = 104
    val INFO_TO_COLLECTOR = "sealdrop/v1/header/to-collector".toByteArray(Charsets.US_ASCII)
    val INFO_TO_SENDER = "sealdrop/v1/header/to-sender".toByteArray(Charsets.US_ASCII)
    private val PAYLOAD_INFO = "sealdrop/v1/payload".toByteArray(Charsets.US_ASCII)
    private val SIG_SENDER = "sealdrop/v1/sig/sender".toByteArray(Charsets.US_ASCII)
    private val SIG_COLLECTOR = "sealdrop/v1/sig/collector".toByteArray(Charsets.US_ASCII)

    fun headerInfo(kind: Int): ByteArray = if (kind == KIND_RECEIPT) INFO_TO_SENDER else INFO_TO_COLLECTOR

    fun statement(kind: Int, digestBeforeSignature: ByteArray): ByteArray =
        (if (kind == KIND_RECEIPT) SIG_COLLECTOR else SIG_SENDER) + byteArrayOf(0) + digestBeforeSignature

    fun nonce(index: Long, last: Boolean): ByteArray =
        ByteBuffer.allocate(12).putShort(0).put(0).putLong(index).put((if (last) 1 else 0).toByte()).array()

    internal fun payloadKey(header: Header): ByteArray = Hkdf.sha256(header.fileKey, header.messageId, PAYLOAD_INFO, 32)

    /**
     * Writes a sealed file of [kind] for [reader], signed by [signer]. [content] gives exactly [n] bytes; it's read
     * piece by piece, so a large bundle never has to fit into memory.
     */
    fun seal(
        out: OutputStream, kind: Int, content: InputStream, n: Long, reader: PublicKey, signer: Signer, created: Long,
        messageId: ByteArray = Encoding.randomBytes(16), fileKey: ByteArray = Encoding.randomBytes(32),
    ): SealResult {
        val header = Header(kind, created, n, messageId, signer.keyId, fileKey)
        val length = header.length
        val count = header.pieces
        val digest = MessageDigest.getInstance("SHA-256")
        fun write(data: ByteArray) {
            out.write(data)
            digest.update(data)
        }

        write(HpkeSuite.seal(reader, headerInfo(kind), header.pack()))
        val cipher = PieceCipher(payloadKey(header))
        val piece = ByteArray(PIECE)
        var left = n
        for (index in 0 until count) {
            val size = minOf(PIECE.toLong(), length - index * PIECE).toInt()
            val take = minOf(left, size.toLong()).toInt()
            readFully(content, piece, take)
            piece.fill(0, take, size)
            left -= take
            write(cipher.seal(index, index == count - 1, piece, size))
        }
        require(content.read() == -1) { "content longer than announced" }
        val signature = signer.sign(statement(kind, (digest.clone() as MessageDigest).digest()))
        check(signature.size == SIGNATURE) { "signature must be 64 bytes" }
        out.write(signature)
        digest.update(signature)
        return SealResult(header, header.sealedSize, Encoding.hex(digest.digest()))
    }

    private fun readFully(input: InputStream, buffer: ByteArray, length: Int) {
        var done = 0
        while (done < length) {
            val got = input.read(buffer, done, length - done)
            if (got < 0) throw IllegalArgumentException("content shorter than announced")
            done += got
        }
    }

    /** Step 1: a size the location can hold, and within the limit (`up/` only). */
    fun checkListedSize(where: Where, size: Long, maxSealed: Long = Sizes.DEFAULT_MAX_SEALED) {
        if (Sizes.lengthForSize(where, size) == null) throw Rejected(Reasons.DAMAGED, "impossible size")
        if (where == Where.UP && size > maxSealed) throw Rejected(Reasons.TOO_BIG)
    }

    /** Step 2: opens the 152-byte prefix with any of the reader's opening keys (the collector's retired ones too). */
    fun openHeader(prefix: ByteArray, openingKeys: List<PrivateKey>, info: ByteArray, expectedKinds: Collection<Int>): Header {
        if (prefix.size != PREFIX) throw Rejected(Reasons.DAMAGED, "short prefix")
        for (key in openingKeys) {
            val raw = HpkeSuite.open(key, info, prefix) ?: continue
            if (raw.size != HEADER_LEN) throw Rejected(Reasons.DAMAGED, "header length")
            return Header.unpack(raw, expectedKinds)
        }
        throw Rejected(Reasons.DAMAGED, "header doesn't open")
    }

    /** All of §4 for a file in memory (receipts, tests): size, header, writer, signature, content. */
    fun openSmall(
        data: ByteArray, openingKeys: List<PrivateKey>, info: ByteArray, expectedKinds: Collection<Int>,
        findVerifier: (Header) -> Verifier?, where: Where, maxSealed: Long = Sizes.DEFAULT_MAX_SEALED,
    ): Pair<Header, ByteArray> {
        checkListedSize(where, data.size.toLong(), maxSealed)
        val sealed = SealedFile(BytesSource(data))
        val header = sealed.openHeader(openingKeys, info, expectedKinds)
        val verifier = findVerifier(header) ?: throw Rejected(Reasons.UNKNOWN_SENDER)
        sealed.verify(verifier)
        return header to sealed.readContent()
    }
}

/** ChaCha20-Poly1305 (RFC 8439) for the pieces: an empty `aad`, the nonce from the piece's number (§4). */
internal class PieceCipher(key: ByteArray) {
    private val key = SecretKeySpec(key, "ChaCha20")
    private val cipher = Cipher.getInstance("ChaCha20/Poly1305/NoPadding")

    fun seal(index: Long, last: Boolean, plain: ByteArray, length: Int): ByteArray {
        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(Sealed.nonce(index, last)))
        return cipher.doFinal(plain, 0, length)
    }

    fun open(index: Long, last: Boolean, sealed: ByteArray): ByteArray? {
        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(Sealed.nonce(index, last)))
        return try {
            cipher.doFinal(sealed)
        } catch (e: AEADBadTagException) {
            null
        }
    }
}

/** A sealed file on disk (or in memory), read in §4's order. */
class SealedFile(private val source: SealedSource) {
    val size: Long get() = source.size
    var header: Header? = null
        private set

    private fun opened(): Header = header ?: throw IllegalStateException("open the header first")

    fun readAt(offset: Long, length: Int): ByteArray {
        val data = try {
            source.readAt(offset, length)
        } catch (e: EOFException) {
            ByteArray(0)
        }
        if (data.size != length) throw Rejected(Reasons.DAMAGED, "file shorter than its size")
        return data
    }

    /** Steps 2 and 3: the header, then the exact size. */
    fun openHeader(openingKeys: List<PrivateKey>, info: ByteArray, expectedKinds: Collection<Int>): Header {
        val header = Sealed.openHeader(readAt(0, PREFIX), openingKeys, info, expectedKinds)
        if (header.sealedSize != size) throw Rejected(Reasons.DAMAGED, "size doesn't match the header")
        this.header = header
        return header
    }

    fun digestBeforeSignature(): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        var offset = 0L
        val end = size - SIGNATURE
        while (offset < end) {
            val chunk = readAt(offset, minOf(PIECE.toLong(), end - offset).toInt())
            digest.update(chunk)
            offset += chunk.size
        }
        return digest.digest()
    }

    /** Step 5: the signature over everything before it. */
    fun verify(verifier: Verifier) {
        val signature = readAt(size - SIGNATURE, SIGNATURE)
        if (!verifier.verify(signature, Sealed.statement(opened().kind, digestBeforeSignature()))) {
            throw Rejected(Reasons.BAD_SIGNATURE)
        }
    }

    /** Step 6: the content, decrypted piece by piece. */
    fun content(checkPadding: Boolean = true): ContentStream = ContentStream(this, opened(), checkPadding)

    /** The whole content in memory; for small files (pairing requests, receipts) and tests. */
    fun readContent(checkPadding: Boolean = true): ByteArray {
        val stream = content(checkPadding)
        val out = stream.readNBytes(Math.toIntExact(opened().n))
        stream.finish()
        paddingOk = stream.paddingOk
        return out
    }

    /** Whether the padding was all zeros, after [readContent] with `checkPadding = false`. */
    var paddingOk: Boolean = true
        private set
}

/**
 * Exactly `n` bytes of content. At the end, the pieces left (padding only) are decrypted too, and the padding is
 * checked: a damaged piece or non-zero padding is [Rejected] (`damaged`) there, as reading reaches the end or
 * [finish] is called.
 */
class ContentStream internal constructor(
    private val file: SealedFile, private val header: Header, private val checkPadding: Boolean,
) : InputStream() {
    private val cipher = PieceCipher(Sealed.payloadKey(header))
    private val length = header.length
    private val count = header.pieces
    private var index = 0L
    private var offset = PREFIX.toLong()
    private var buffer = ByteArray(0)
    private var position = 0
    private var available = 0
    private var left = header.n
    private var finished = false

    var paddingOk = true
        private set

    private fun nextPiece(): Boolean {
        if (index >= count) return false
        val plainSize = minOf(PIECE.toLong(), length - index * PIECE).toInt()
        val sealed = file.readAt(offset, plainSize + TAG)
        offset += plainSize + TAG
        val plain = cipher.open(index, index == count - 1, sealed)
            ?: throw Rejected(Reasons.DAMAGED, "piece $index doesn't open")
        index++
        val take = minOf(left, plain.size.toLong()).toInt()
        for (i in take until plain.size) if (plain[i] != 0.toByte()) paddingOk = false
        left -= take
        buffer = plain
        position = 0
        available = take
        return true
    }

    override fun read(): Int {
        val one = ByteArray(1)
        return if (read(one, 0, 1) < 0) -1 else one[0].toInt() and 0xFF
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0
        while (position == available) {
            if (left == 0L) {
                finish()
                return -1
            }
            check(nextPiece()) { "content longer than the pieces" }
        }
        val n = minOf(len, available - position)
        System.arraycopy(buffer, position, b, off, n)
        position += n
        return n
    }

    /** Decrypts the pieces after the content, then checks the padding. */
    fun finish() {
        if (finished) return
        while (nextPiece()) Unit
        finished = true
        if (checkPadding && !paddingOk) throw Rejected(Reasons.DAMAGED, "padding isn't zero")
    }
}

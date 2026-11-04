package app.sealdrop.net

import android.util.Xml
import app.sealdrop.core.Encoding
import app.sealdrop.core.Hkdf
import org.xmlpull.v1.XmlPullParser
import java.io.ByteArrayInputStream
import java.io.IOException
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/** The storage answered with an error. [retryAfter]: seconds, from `Retry-After`, or -1. */
class S3Error(val status: Int, val code: String, val text: String, val retryAfter: Long = -1) :
    IOException("$status $code") {
    /** §8: Backblaze's wording when an account's cap or free limit stops requests. */
    val capExceeded get() = (status == 401 || status == 403) && text.lowercase().contains("cap exceeded")
    val refused get() = status == 401 || status == 403
    val clockWrong get() = code == "RequestTimeTooSkewed"
    val retryable get() = status == 429 || status >= 500
}

/** One entry of `ListObjectsV2`. */
class Listed(val name: String, val etag: String, val size: Long)

/**
 * The S3 requests Sealdrop makes (PROTOCOL.md §8), path style, signed with AWS Signature Version 4 over the body.
 * One location's key: it never holds another. Every request goes through [gate].
 */
class S3(
    endpoint: String,
    private val region: String,
    private val keyId: String,
    private val secret: String,
    private val gate: Gate,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val host = Gate.hostOf(endpoint)
    private val hostHeader = if (host.port == 443) host.name else "${host.name}:${host.port}"
    private val base = "https://$hostHeader"

    override fun toString() = "S3($hostHeader)" // never the key

    fun put(bucket: String, name: String, body: ByteArray) {
        request("PUT", bucket, name, headers = BINARY, body = body)
    }

    fun createMultipart(bucket: String, name: String): String {
        val reply = request("POST", bucket, name, listOf("uploads" to ""), BINARY)
        return Xmls.text(reply, "UploadId") ?: throw S3Error(0, "BadReply", "no UploadId")
    }

    fun uploadPart(bucket: String, name: String, uploadId: String, number: Int, body: ByteArray): String {
        var etag: String? = null
        request("PUT", bucket, name, listOf("partNumber" to "$number", "uploadId" to uploadId), BINARY, body) { etag = it }
        return etag ?: throw S3Error(0, "BadReply", "no ETag")
    }

    fun completeMultipart(bucket: String, name: String, uploadId: String, etags: List<String>) {
        val parts = etags.withIndex().joinToString("") { (i, etag) ->
            "<Part><PartNumber>${i + 1}</PartNumber><ETag>${escape(etag)}</ETag></Part>"
        }
        val body = "<CompleteMultipartUpload>$parts</CompleteMultipartUpload>".toByteArray()
        val reply = request("POST", bucket, name, listOf("uploadId" to uploadId), XML, body)
        if (Xmls.root(reply) == "Error") throw error(200, reply) // S3 may answer 200 and still have failed
    }

    fun abortMultipart(bucket: String, name: String, uploadId: String) {
        request("DELETE", bucket, name, listOf("uploadId" to uploadId), ok = setOf(200, 204))
    }

    /** One page of `ListObjectsV2`, and the token for the next one (null: that was the last). */
    fun list(bucket: String, prefix: String, token: String?): Pair<List<Listed>, String?> {
        val query = listOf("list-type" to "2", "prefix" to prefix) + (token?.let { listOf("continuation-token" to it) } ?: emptyList())
        return Xmls.listing(request("GET", bucket, "", query))
    }

    /** A small object (a receipt), whole. */
    fun get(bucket: String, name: String, limit: Int = 1 shl 20): ByteArray = request("GET", bucket, name, limit = limit)

    // --- the request ------------------------------------------------------------------------------------------------

    private fun request(
        method: String, bucket: String, name: String, query: List<Pair<String, String>> = emptyList(),
        headers: Map<String, String> = emptyMap(), body: ByteArray = ByteArray(0), ok: Set<Int> = setOf(200),
        limit: Int = 1 shl 20, onEtag: ((String?) -> Unit)? = null,
    ): ByteArray {
        require(method != "PUT" && method != "POST" || "Content-Type" in headers) { "a body without its type" }
        val path = if (name.isEmpty()) "/$bucket" else "/$bucket/$name"
        val bodySha = Encoding.hex(Encoding.sha256(body))
        val signed = SigV4.sign(method, hostHeader, path, query, headers, bodySha, keyId, secret, region, clock())
        var target = SigV4.uriEncode(path, keepSlash = true)
        if (query.isNotEmpty()) {
            target += "?" + query.joinToString("&") { (k, v) ->
                SigV4.uriEncode(k) + if (v.isEmpty()) "" else "=" + SigV4.uriEncode(v)
            }
        }
        val connection = gate.open(URL(base + target))
        try {
            connection.requestMethod = method
            for ((k, v) in signed) if (k != "host") connection.setRequestProperty(k, v)
            if (method == "PUT" || method == "POST") {
                connection.doOutput = true
                connection.setFixedLengthStreamingMode(body.size)
                connection.outputStream.use { it.write(body) }
            }
            val status = connection.responseCode
            onEtag?.invoke(connection.getHeaderField("ETag"))
            val stream = if (status < 400) connection.inputStream else connection.errorStream
            val data = stream?.use { readLimited(it, limit) } ?: ByteArray(0)
            if (status !in ok) {
                val retryAfter = connection.getHeaderField("Retry-After")?.toLongOrNull() ?: -1
                throw error(status, data, retryAfter)
            }
            return data
        } finally {
            connection.disconnect()
        }
    }

    private fun readLimited(input: java.io.InputStream, limit: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(64 * 1024)
        while (true) {
            val n = input.read(buffer)
            if (n < 0) break
            out.write(buffer, 0, n)
            if (out.size() > limit) throw S3Error(0, "BadReply", "reply too long")
        }
        return out.toByteArray()
    }

    private fun error(status: Int, body: ByteArray, retryAfter: Long = -1): S3Error {
        val (code, message) = try {
            (Xmls.text(body, "Code") ?: "?") to (Xmls.text(body, "Message") ?: "")
        } catch (e: Exception) {
            "?" to ""
        }
        return S3Error(status, code, message, retryAfter)
    }

    private fun escape(text: String) = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    private companion object {
        // Every request with a body names its type, signed: without one, Android's HTTP client sends
        // `application/x-www-form-urlencoded`, and the storage then reads the body as form fields and the signature
        // fails (Backblaze: on CompleteMultipartUpload).
        val BINARY = mapOf("Content-Type" to "application/octet-stream")
        val XML = mapOf("Content-Type" to "application/xml")
    }
}

/** AWS Signature Version 4, exactly as the collector's (`collector/sealdrop/s3.py`), tested with AWS's examples. */
object SigV4 {
    private const val UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"

    /** Everything but `A–Z a–z 0–9 - _ . ~` as UTF-8 %XX (and `/` too, unless kept). */
    fun uriEncode(text: String, keepSlash: Boolean = false): String = buildString {
        for (b in text.toByteArray(Charsets.UTF_8)) {
            val c = (b.toInt() and 0xFF).toChar()
            if (c in UNRESERVED || (keepSlash && c == '/')) append(c) else append("%%%02X".format(b.toInt() and 0xFF))
        }
    }

    fun amzDate(millis: Long): String = SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'", Locale.ROOT)
        .apply { timeZone = TimeZone.getTimeZone("UTC") }.format(Date(millis))

    /** The headers to send: [headers] plus host, x-amz-date, x-amz-content-sha256 and Authorization, all signed. */
    fun sign(
        method: String, host: String, path: String, query: List<Pair<String, String>>, headers: Map<String, String>,
        bodySha256: String, keyId: String, secret: String, region: String, whenMillis: Long, service: String = "s3",
    ): Map<String, String> {
        val date = amzDate(whenMillis)
        val sent = LinkedHashMap(headers).apply {
            put("host", host)
            put("x-amz-date", date)
            put("x-amz-content-sha256", bodySha256)
        }
        val canonicalHeaders = sent.entries.associate { (k, v) -> k.lowercase() to v.trim().split(Regex("\\s+")).joinToString(" ") }
        val names = canonicalHeaders.keys.sorted()
        val canonicalQuery = query.map { (k, v) -> uriEncode(k) to uriEncode(v) }
            .sortedWith(compareBy({ it.first }, { it.second }))
            .joinToString("&") { (k, v) -> "$k=$v" }
        val canonical = listOf(
            method,
            uriEncode(path, keepSlash = true),
            canonicalQuery,
            names.joinToString("") { "$it:${canonicalHeaders[it]}\n" },
            names.joinToString(";"),
            bodySha256,
        ).joinToString("\n")
        val scope = "${date.substring(0, 8)}/$region/$service/aws4_request"
        val toSign = listOf("AWS4-HMAC-SHA256", date, scope, Encoding.hex(Encoding.sha256(canonical.toByteArray()))).joinToString("\n")
        var key = Hkdf.hmac(("AWS4$secret").toByteArray(), date.substring(0, 8).toByteArray())
        for (part in listOf(region, service, "aws4_request")) key = Hkdf.hmac(key, part.toByteArray())
        val signature = Encoding.hex(Hkdf.hmac(key, toSign.toByteArray()))
        sent["Authorization"] = "AWS4-HMAC-SHA256 Credential=$keyId/$scope, SignedHeaders=${names.joinToString(";")}, Signature=$signature"
        return sent
    }
}

/** The few XML replies S3 sends, read with the platform's pull parser; S3's namespace is ignored. */
internal object Xmls {
    private fun parser(data: ByteArray): XmlPullParser = Xml.newPullParser().apply {
        setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, false)
        setInput(ByteArrayInputStream(data), "UTF-8")
    }

    fun root(data: ByteArray): String? {
        val p = parser(data)
        while (p.next() != XmlPullParser.END_DOCUMENT) if (p.eventType == XmlPullParser.START_TAG) return p.name
        return null
    }

    /** The text of the first element named [tag], anywhere. */
    fun text(data: ByteArray, tag: String): String? {
        val p = parser(data)
        while (p.next() != XmlPullParser.END_DOCUMENT) {
            if (p.eventType == XmlPullParser.START_TAG && p.name == tag) return p.nextText()
        }
        return null
    }

    fun listing(data: ByteArray): Pair<List<Listed>, String?> {
        val p = parser(data)
        val found = mutableListOf<Listed>()
        var truncated = false
        var token: String? = null
        var key: String? = null
        var etag = ""
        var size = 0L
        var depth = 0
        while (p.next() != XmlPullParser.END_DOCUMENT) {
            when (p.eventType) {
                XmlPullParser.START_TAG -> {
                    depth++
                    when {
                        p.name == "Contents" -> { key = null; etag = ""; size = 0 }
                        depth == 3 && p.name == "Key" -> { key = p.nextText(); depth-- }
                        depth == 3 && p.name == "ETag" -> { etag = p.nextText(); depth-- }
                        depth == 3 && p.name == "Size" -> { size = p.nextText().toLong(); depth-- }
                        depth == 2 && p.name == "IsTruncated" -> { truncated = p.nextText() == "true"; depth-- }
                        depth == 2 && p.name == "NextContinuationToken" -> { token = p.nextText(); depth-- }
                    }
                }
                XmlPullParser.END_TAG -> {
                    if (p.name == "Contents") key?.let { found += Listed(it, etag, size) }
                    depth--
                }
            }
        }
        return found to (if (truncated) token else null)
    }
}

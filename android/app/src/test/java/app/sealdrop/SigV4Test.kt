package app.sealdrop

import app.sealdrop.core.Encoding
import app.sealdrop.net.SigV4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Signature Version 4 against AWS's published examples for S3 ("Transferring Payload in a Single Chunk"), the same
 * as the collector's tests (collector/tests/test_s3.py): both sides sign alike.
 */
class SigV4Test {
    private val keyId = "AKIAIOSFODNN7EXAMPLE"
    private val secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    private val host = "examplebucket.s3.amazonaws.com"
    private val time = 1369353600000L // 2013-05-24T00:00:00Z
    private val empty = Encoding.hex(Encoding.sha256(ByteArray(0)))

    private fun signature(h: Map<String, String>) = h.getValue("Authorization").substringAfterLast("Signature=")

    @Test
    fun getObject() {
        val h = SigV4.sign("GET", host, "/test.txt", emptyList(), mapOf("Range" to "bytes=0-9"), empty, keyId, secret, "us-east-1", time)
        assertTrue(h.getValue("Authorization").contains("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,"))
        assertEquals("f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41", signature(h))
    }

    @Test
    fun putObject() {
        val body = "Welcome to Amazon S3.".toByteArray()
        val h = SigV4.sign(
            "PUT", host, "/test\$file.text", emptyList(),
            mapOf("Date" to "Fri, 24 May 2013 00:00:00 GMT", "x-amz-storage-class" to "REDUCED_REDUNDANCY"),
            Encoding.hex(Encoding.sha256(body)), keyId, secret, "us-east-1", time,
        )
        assertEquals("98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd", signature(h))
    }

    @Test
    fun queryWithoutValue() {
        val h = SigV4.sign("GET", host, "/", listOf("lifecycle" to ""), emptyMap(), empty, keyId, secret, "us-east-1", time)
        assertEquals("fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543", signature(h))
    }

    @Test
    fun listing() {
        val h = SigV4.sign("GET", host, "/", listOf("prefix" to "J", "max-keys" to "2"), emptyMap(), empty, keyId, secret, "us-east-1", time)
        assertEquals("34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7", signature(h))
        assertEquals("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request",
            h.getValue("Authorization").split(", ")[0])
    }

    @Test
    fun encoding() {
        assertEquals("a%20b/c~d_e.f-g%2Bh%3D", SigV4.uriEncode("a b/c~d_e.f-g+h=", keepSlash = true))
        assertEquals("up%2Fx", SigV4.uriEncode("up/x"))
        assertEquals("%C3%A9", SigV4.uriEncode("é"))
    }
}

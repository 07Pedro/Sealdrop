package app.sealdrop.core

/**
 * JSON as PROTOCOL.md §3 allows it: UTF-8 without a byte-order mark, I-JSON (RFC 7493), no duplicate names, no
 * numbers with a fraction or exponent, integers only from 0 to 2^53 − 1, no NaN or infinities, no unpaired surrogates
 * (also as `\u` escapes), at most 8 levels deep.
 *
 * Values: objects as [Map] (in the order they were written), arrays as [List], integers as [Long], and [String],
 * [Boolean] and null. Written compactly, byte for byte as the collector writes it (Python's `json.dumps` with
 * `ensure_ascii=False` and no spaces).
 */
object Json {
    const val MAX_INT = (1L shl 53) - 1
    const val MAX_DEPTH = 8

    fun parse(data: ByteArray): Any? {
        if (data.size >= 3 && data[0] == 0xEF.toByte() && data[1] == 0xBB.toByte() && data[2] == 0xBF.toByte()) {
            throw FormatException("byte-order mark")
        }
        return Parser(decodeUtf8(data)).document()
    }

    fun write(value: Any?): ByteArray = StringBuilder().also { writeValue(it, value) }.toString().toByteArray(Charsets.UTF_8)

    /** Strict UTF-8 (RFC 3629): no overlong forms, no surrogates, nothing above U+10FFFF. */
    private fun decodeUtf8(data: ByteArray): String {
        val out = StringBuilder(data.size)
        var i = 0
        fun next(): Int {
            val b = data.getOrNull(++i)?.toInt()?.and(0xFF) ?: throw FormatException("not UTF-8")
            if (b and 0xC0 != 0x80) throw FormatException("not UTF-8")
            return b and 0x3F
        }
        while (i < data.size) {
            val b0 = data[i].toInt() and 0xFF
            val cp = when (b0) {
                in 0x00..0x7F -> b0
                in 0xC2..0xDF -> ((b0 and 0x1F) shl 6) or next()
                in 0xE0..0xEF -> (((b0 and 0x0F) shl 12) or (next() shl 6) or next())
                    .also { if (it < 0x800 || it in 0xD800..0xDFFF) throw FormatException("not UTF-8") }
                in 0xF0..0xF4 -> (((b0 and 0x07) shl 18) or (next() shl 12) or (next() shl 6) or next())
                    .also { if (it !in 0x10000..0x10FFFF) throw FormatException("not UTF-8") }
                else -> throw FormatException("not UTF-8")
            }
            out.appendCodePoint(cp)
            i++
        }
        return out.toString()
    }

    private class Parser(private val s: String) {
        private var i = 0

        fun document(): Any? {
            space()
            val value = value(1)
            space()
            if (i != s.length) fail("text after the value")
            return value
        }

        private fun fail(what: String): Nothing = throw FormatException("not JSON: $what")

        private fun space() {
            while (i < s.length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++
        }

        private fun value(depth: Int): Any? {
            if (i >= s.length) fail("unexpected end")
            return when (s[i]) {
                '{' -> obj(depth)
                '[' -> array(depth)
                '"' -> string()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                '-' -> throw FormatException("negative number")
                in '0'..'9' -> number()
                else -> fail("unexpected character")
            }
        }

        private fun literal(word: String, value: Boolean?): Boolean? {
            if (!s.startsWith(word, i)) fail("unexpected character")
            i += word.length
            return value
        }

        private fun number(): Long {
            val start = i
            if (s[i] == '0') i++ else while (i < s.length && s[i] in '0'..'9') i++
            if (i < s.length && (s[i] == '.' || s[i] == 'e' || s[i] == 'E')) {
                throw FormatException("number with a fraction or exponent")
            }
            if (i < s.length && s[i] in '0'..'9') fail("leading zero")
            val digits = s.substring(start, i)
            val value = if (digits.length > 16) null else digits.toLong()
            if (value == null || value > MAX_INT) throw FormatException("integer above 2^53 - 1")
            return value
        }

        private fun string(): String {
            i++ // the opening quote
            val out = StringBuilder()
            while (true) {
                if (i >= s.length) fail("unterminated string")
                val c = s[i++]
                when {
                    c == '"' -> break
                    c == '\\' -> {
                        if (i >= s.length) fail("unterminated string")
                        when (val e = s[i++]) {
                            '"', '\\', '/' -> out.append(e)
                            'b' -> out.append('\b')
                            'f' -> out.append('\u000C')
                            'n' -> out.append('\n')
                            'r' -> out.append('\r')
                            't' -> out.append('\t')
                            'u' -> {
                                if (i + 4 > s.length) fail("bad \\u escape")
                                var code = 0
                                repeat(4) { code = code * 16 + hexDigit(s[i++]) }
                                out.append(code.toChar())
                            }
                            else -> fail("bad escape")
                        }
                    }
                    c < ' ' -> fail("control character in a string")
                    else -> out.append(c)
                }
            }
            return out.toString().also { checkSurrogates(it) }
        }

        /** ASCII hex only (`Character.digit` would take other scripts' digits too). */
        private fun hexDigit(c: Char): Int = when (c) {
            in '0'..'9' -> c - '0'
            in 'a'..'f' -> c - 'a' + 10
            in 'A'..'F' -> c - 'A' + 10
            else -> fail("bad \\u escape")
        }

        private fun obj(depth: Int): Map<String, Any?> {
            if (depth > MAX_DEPTH) throw FormatException("nested deeper than 8")
            i++
            val out = LinkedHashMap<String, Any?>()
            space()
            if (i < s.length && s[i] == '}') {
                i++
                return out
            }
            while (true) {
                space()
                if (i >= s.length || s[i] != '"') fail("expected a name")
                val key = string()
                space()
                if (i >= s.length || s[i] != ':') fail("expected ':'")
                i++
                space()
                if (key in out) throw FormatException("duplicate name: ${key.take(40)}")
                out[key] = value(depth + 1)
                space()
                when (if (i < s.length) s[i++] else fail("unexpected end")) {
                    ',' -> continue
                    '}' -> return out
                    else -> fail("expected ',' or '}'")
                }
            }
        }

        private fun array(depth: Int): List<Any?> {
            if (depth > MAX_DEPTH) throw FormatException("nested deeper than 8")
            i++
            val out = ArrayList<Any?>()
            space()
            if (i < s.length && s[i] == ']') {
                i++
                return out
            }
            while (true) {
                space()
                out.add(value(depth + 1))
                space()
                when (if (i < s.length) s[i++] else fail("unexpected end")) {
                    ',' -> continue
                    ']' -> return out
                    else -> fail("expected ',' or ']'")
                }
            }
        }
    }

    private fun checkSurrogates(text: String) {
        var i = 0
        while (i < text.length) {
            val c = text[i]
            if (Character.isHighSurrogate(c) && i + 1 < text.length && Character.isLowSurrogate(text[i + 1])) {
                i += 2
                continue
            }
            if (Character.isSurrogate(c)) throw FormatException("unpaired surrogate")
            i++
        }
    }

    private fun writeValue(out: StringBuilder, value: Any?) {
        when (value) {
            null -> out.append("null")
            is Boolean -> out.append(value)
            is Int, is Long -> {
                val n = (value as Number).toLong()
                require(n in 0..MAX_INT) { "integer outside 0 … 2^53 − 1" }
                out.append(n)
            }
            is String -> writeString(out, value)
            is Map<*, *> -> {
                out.append('{')
                var first = true
                for ((k, v) in value) {
                    require(k is String) { "object names must be strings" }
                    if (!first) out.append(',')
                    first = false
                    writeString(out, k)
                    out.append(':')
                    writeValue(out, v)
                }
                out.append('}')
            }
            is List<*> -> {
                out.append('[')
                value.forEachIndexed { index, v ->
                    if (index > 0) out.append(',')
                    writeValue(out, v)
                }
                out.append(']')
            }
            else -> throw IllegalArgumentException("not a JSON value: ${value::class.java.simpleName}")
        }
    }

    private const val HEX = "0123456789abcdef"

    private fun writeString(out: StringBuilder, text: String) {
        checkSurrogates(text)
        out.append('"')
        for (c in text) {
            when {
                c == '"' -> out.append("\\\"")
                c == '\\' -> out.append("\\\\")
                c == '\n' -> out.append("\\n")
                c == '\r' -> out.append("\\r")
                c == '\t' -> out.append("\\t")
                c == '\b' -> out.append("\\b")
                c == '\u000C' -> out.append("\\f")
                c < ' ' -> out.append("\\u00").append(HEX[c.code shr 4]).append(HEX[c.code and 15])
                else -> out.append(c)
            }
        }
        out.append('"')
    }
}

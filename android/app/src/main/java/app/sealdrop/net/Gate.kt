package app.sealdrop.net

import java.io.IOException
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * The one place in Sealdrop that opens network connections (PROTOCOL.md §9.5). Only HTTPS, and only to the hosts
 * from pairing, checked before every connection. The system's certificate authorities only and no cleartext come
 * from the network security config; redirects are never followed; 15 s to connect, 60 s without data.
 */
class Gate(private val allowed: () -> Set<Host>) {
    /** A host and port as an endpoint names them (`https://host[:port]`). */
    data class Host(val name: String, val port: Int)

    class Refused(host: String) : IOException("not a host from pairing: $host")

    fun open(url: URL): HttpsURLConnection {
        if (url.protocol != "https") throw Refused(url.toString())
        val host = Host(url.host.lowercase(), if (url.port == -1) 443 else url.port)
        if (host !in allowed()) throw Refused(host.name)
        return (url.openConnection() as HttpsURLConnection).apply {
            instanceFollowRedirects = false
            connectTimeout = 15_000
            readTimeout = 60_000
            useCaches = false
            setRequestProperty("User-Agent", "sealdrop")
        }
    }

    companion object {
        /** The host of an endpoint from the QR code (`https://host[:port]`, already checked by Pairing.checkOffer). */
        fun hostOf(endpoint: String): Host {
            val url = URL(endpoint)
            return Host(url.host.lowercase(), if (url.port == -1) 443 else url.port)
        }
    }
}

package app.sealdrop

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * "Talks only to the storage" (PROTOCOL.md §9.5), checked in the sources: one place opens connections (the gate), the
 * network classes appear nowhere else, no network library is used, and the manifest asks for nothing more than §9.5
 * allows. The gate's own check of each host is tested on the device (GateTest), and the end-to-end run watches the
 * app's connections (tools/e2e).
 */
class OnlyStorageTest {
    private val sources = File(System.getProperty("sealdrop.sources") ?: "src/main/java")
    private val files = sources.walk().filter { it.isFile && it.extension == "kt" }.toList()
    private fun rel(f: File) = f.relativeTo(sources).invariantSeparatorsPath

    @Test
    fun sourcesFound() = assertTrue("no sources under $sources", files.size > 10)

    @Test
    fun onlyTheGateOpensConnections() {
        val opening = Regex("""openConnection\(|\bSocket\(|SocketChannel|DatagramSocket|HttpClient|URLConnection\b|openStream\(""")
        for (f in files) {
            if (rel(f) == "app/sealdrop/net/Gate.kt") continue
            val hits = f.readLines().withIndex().filter { opening.containsMatchIn(it.value) }
            assertTrue("${rel(f)} opens connections: ${hits.map { it.index + 1 }}", hits.isEmpty())
        }
    }

    @Test
    fun networkClassesOnlyInNet() {
        for (f in files) {
            if (rel(f).startsWith("app/sealdrop/net/")) continue
            val hits = f.readLines().filter { it.startsWith("import java.net.") || it.startsWith("import javax.net.") }
            assertTrue("${rel(f)} uses the network classes: $hits", hits.isEmpty())
        }
    }

    @Test
    fun onlyS3UsesTheGate() {
        for (f in files) {
            if (rel(f) == "app/sealdrop/net/S3.kt" || rel(f) == "app/sealdrop/net/Gate.kt") continue
            assertTrue("${rel(f)} opens through the gate", f.readLines().none { it.contains("gate.open(") })
        }
    }

    @Test
    fun noNetworkLibraries() {
        val words = listOf("okhttp", "retrofit", "ktor", "WebView", "DownloadManager", "firebase", "com.google.android.gms", "Volley")
        for (f in files) {
            val text = f.readText()
            for (w in words) assertTrue("${rel(f)} mentions $w", !text.contains(w))
        }
        val build = File(sources, "../../../build.gradle.kts").readText()
        for (w in listOf("okhttp", "retrofit", "ktor", "firebase", "play-services")) assertTrue("build uses $w", !build.contains(w))
    }

    @Test
    fun manifestAsksOnlyForWhatIsAllowed() {
        val manifest = File(sources, "../AndroidManifest.xml").readText()
        val asked = Regex("""uses-permission android:name="([^"]+)"""").findAll(manifest).map { it.groupValues[1] }.toSet()
        assertEquals(
            setOf(
                "android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE", "android.permission.CAMERA",
                "android.permission.POST_NOTIFICATIONS", "android.permission.RECEIVE_BOOT_COMPLETED",
            ),
            asked,
        )
        assertTrue(manifest.contains("""android:networkSecurityConfig="@xml/network_security_config""""))
        assertTrue(manifest.contains("""android:allowBackup="false""""))
        val config = File(sources, "../res/xml/network_security_config.xml").readText()
        assertTrue(config.contains("""cleartextTrafficPermitted="false""""))
        assertTrue(config.contains("""<certificates src="system" />"""))
        assertTrue("user certificates must not be trusted", !config.contains("""src="user""""))
    }
}

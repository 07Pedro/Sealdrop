package app.sealdrop.ui

import android.graphics.Bitmap
import androidx.activity.ComponentActivity
import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.requiredSize
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.Image
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.unit.dp
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.sealdrop.R
import app.sealdrop.ui.theme.SealdropTheme
import kotlinx.coroutines.runBlocking
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Draws every screen with made-up data and saves it to `Android/data/app.sealdrop/files/previews/`, for the preview
 * sheets that are agreed on before the app is built further. Run on the emulator:
 *
 *     adb shell am instrument -w -e class app.sealdrop.ui.PreviewShotsTest app.sealdrop.test/androidx.test.runner.AndroidJUnitRunner
 */
@RunWith(AndroidJUnit4::class)
class PreviewShotsTest {
    @get:Rule
    val rule = createAndroidComposeRule<ComponentActivity>()

    private val outDir = File(InstrumentationRegistry.getInstrumentation().targetContext.getExternalFilesDir(null), "previews")
        .apply { deleteRecursively(); mkdirs() }

    private val tracker = AppUi("Example Tracker", "org.example.tracker", "Approved · last delivery today 14:31")
    private val notes = AppUi("Field Notes", "org.example.notes", "Approved · last delivery on Monday")
    private val fingerprint = "K7Q2M3XD4HTBWPLA"
    private val host = "s3.us-west-004.backblazeb2.com"

    private val good = StatusUi(
        fingerprint = fingerprint, label = "Phone", storageHost = host,
        lastUpload = "today 14:32 · 1 delivery, 0.2 MB", lastPickup = "5 minutes ago", lastBackup = "today 03:10",
        onPhone = null, network = "Wi-Fi", apps = listOf(tracker, notes),
    )
    private val troubled = good.copy(
        lastUpload = "yesterday 18:05 · 3 deliveries, 41 MB", lastPickup = "3 days ago",
        onPhone = "4 deliveries, 38 MB · 1 waits for Wi-Fi", network = "Mobile data: small items only",
        warnings = listOf(WarningUi(WarningKind.STORAGE_LIMIT), WarningUi(WarningKind.WAITING, "3 days")),
        holds = listOf(HoldUi("Example Tracker", "09:12")),
        failed = listOf(FailedUi("Field Notes", "2.1 MB", "since yesterday", "a file's checksum didn't match")),
    )

    /** One image. `scroll` is how far down a long screen is scrolled: 0 is the top, 1 the end. */
    private class Shot(val name: String, val dark: Boolean, val scroll: Float = 0f,
                       val content: @Composable (ScrollState) -> Unit)

    private val shots = listOf(
        Shot("00-icon", dark = false) { IconSheet() },
        Shot("01-welcome", dark = false) { WelcomeScreen() },
        Shot("02-scan", dark = true) { ScanScreen(fakeCamera = true) },
        Shot("03-scan-expired", dark = true) {
            ScanScreen("This QR code has expired. Run the pair command on your server again, and scan the new code.",
                fakeCamera = true)
        },
        Shot("04-name", dark = false) { NameScreen("Phone", host, "inbox-example", minutesLeft = 8) },
        Shot("05-compare", dark = false) { CompareScreen(fingerprint) },
        Shot("06-paired", dark = false) { PairedScreen() },
        Shot("07-approve", dark = false) {
            ApproveScreen(AppUi("Example Tracker", "org.example.tracker"),
                "3f9a1c07b2e84d5a96c0e1f27d38a4b5c6e7f8091a2b3c4d5e6f708192a3b4c5")
        },
        Shot("08-status", dark = false) { StatusScreen(good, scroll = it) },
        Shot("09-status-dark", dark = true) { StatusScreen(good, scroll = it) },
        Shot("10-status-needs-a-look", dark = false) { StatusScreen(troubled, scroll = it) },
        Shot("11-status-needs-a-look-middle", dark = false, scroll = 0.5f) { StatusScreen(troubled, scroll = it) },
        Shot("12-status-needs-a-look-end", dark = false, scroll = 1f) { StatusScreen(troubled, scroll = it) },
        Shot("13-status-needs-a-look-dark", dark = true) { StatusScreen(troubled, scroll = it) },
        Shot("14-settings", dark = false) { SettingsScreen(good, "0.1.0", scroll = it) },
        Shot("15-settings-dark", dark = true) { SettingsScreen(good, "0.1.0", scroll = it) },
        Shot("16-welcome-dark", dark = true) { WelcomeScreen() },
        Shot("17-compare-dark", dark = true) { CompareScreen(fingerprint) },
    )

    @Test
    fun drawEveryScreen() {
        var index by mutableIntStateOf(0)
        val scrolls = shots.map { ScrollState(0) }
        rule.mainClock.autoAdvance = false // the progress indicator and the text cursor never stop moving
        rule.setContent {
            val shot = shots[index]
            SealdropTheme(darkTheme = shot.dark) { Surface { shot.content(scrolls[index]) } }
        }
        for ((i, shot) in shots.withIndex()) {
            index = i
            rule.mainClock.advanceTimeBy(800)
            if (shot.scroll > 0f) {
                rule.runOnIdle { runBlocking { scrolls[i].scrollTo((scrolls[i].maxValue * shot.scroll).toInt()) } }
                rule.mainClock.advanceTimeBy(200)
            }
            val bitmap = rule.onRoot().captureToImage().asAndroidBitmap()
            File(outDir, "${shot.name}.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
        }
    }
}

/** The app icon as a launcher shows it: masked to a circle and a rounded square, and the themed (one-colour) one. */
@Composable
private fun IconSheet() {
    Box(Modifier.fillMaxSize().background(Color(0xFFDDE4E3)), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(32.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(32.dp)) {
                Labelled("Round") { LauncherIcon(CircleShape, themed = false) }
                Labelled("Rounded square") { LauncherIcon(RoundedCornerShape(36.dp), themed = false) }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(32.dp)) {
                Labelled("Themed icons") { LauncherIcon(CircleShape, themed = true) }
                Labelled("In the app") { Box(Modifier.size(144.dp), Alignment.Center) { AppMark(120.dp) } }
            }
        }
    }
}

@Composable
private fun Labelled(label: String, content: @Composable () -> Unit) {
    Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        content()
        Text(label, style = MaterialTheme.typography.titleMedium, color = Color(0xFF3F4948))
    }
}

@Composable
private fun LauncherIcon(shape: androidx.compose.ui.graphics.Shape, themed: Boolean) {
    Box(
        Modifier.size(144.dp).clip(shape).background(if (themed) Color(0xFFCCE8E7) else Color(0xFF00696B)),
        contentAlignment = Alignment.Center,
    ) {
        Image(
            painterResource(if (themed) R.drawable.ic_launcher_monochrome else R.drawable.ic_launcher_foreground), null,
            Modifier.requiredSize(144.dp * 108f / 72f),
            colorFilter = if (themed) ColorFilter.tint(Color(0xFF00393A)) else null,
        )
    }
}

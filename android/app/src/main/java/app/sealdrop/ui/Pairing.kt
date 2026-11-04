package app.sealdrop.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.sealdrop.R
import app.sealdrop.ui.theme.SealdropTheme
import kotlin.random.Random

/** The first screen, before pairing: what Sealdrop does, and the three steps of pairing (docs/PROTOCOL.md §7). */
@Composable
fun WelcomeScreen(onScan: () -> Unit = {}) {
    Scaffold { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(horizontal = 24.dp),
        ) {
            Spacer(Modifier.height(40.dp))
            AppMark(72.dp)
            Spacer(Modifier.height(24.dp))
            Text("Send files to your own server", style = MaterialTheme.typography.headlineMedium)
            Spacer(Modifier.height(12.dp))
            Text(
                "Apps you approve hand files to Sealdrop. It locks them so that only your server can open them, " +
                    "signs them, and puts them into your storage bucket. Your server picks them up from there. The " +
                    "storage provider can't read anything.",
                style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(24.dp))
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
                Column(Modifier.padding(16.dp)) {
                    Text("To pair this phone", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(8.dp))
                    Step(1, "On your server, run the collector's pair command. It shows a QR code.")
                    Step(2, "Scan that QR code with this phone.")
                    Step(3, "Check that both screens show the same short code.")
                }
            }
            Spacer(Modifier.weight(1f).height(32.dp))
            Button(onScan, Modifier.fillMaxWidth().height(56.dp)) {
                Icon(painterResource(R.drawable.ic_qr_code_scanner), null, Modifier.size(ButtonDefaults.IconSize))
                Spacer(Modifier.width(ButtonDefaults.IconSpacing))
                Text("Scan the QR code", style = MaterialTheme.typography.titleMedium)
            }
            Text(
                "The camera is used only for this, and only this time.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth().padding(top = 12.dp, bottom = 24.dp),
            )
        }
    }
}

/** The camera, with a frame to aim. `error`: why the last code didn't work. The camera feed itself is drawn by
 *  CameraX behind this (`camera`); the previews draw a stand-in (`fakeCamera`). */
@Composable
fun ScanScreen(
    error: String? = null, fakeCamera: Boolean = false, onCancel: () -> Unit = {}, camera: (@Composable () -> Unit)? = null,
) {
    Box(Modifier.fillMaxSize().background(Color.Black)) {
        if (fakeCamera) FakeCameraView() else camera?.invoke()
        Canvas(Modifier.fillMaxSize()) { drawFrame() }
        Column(Modifier.fillMaxSize().safeDrawingPadding().padding(24.dp)) {
            Text(
                "Point the camera at the QR code on your server's screen",
                style = MaterialTheme.typography.titleLarge, color = Color.White, textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth().padding(top = 32.dp),
            )
            Spacer(Modifier.weight(1f))
            if (error != null) {
                Card(
                    Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer,
                        contentColor = MaterialTheme.colorScheme.onErrorContainer,
                    ),
                ) {
                    Row(Modifier.padding(16.dp)) {
                        Icon(painterResource(R.drawable.ic_error), null)
                        Spacer(Modifier.width(12.dp))
                        Text(error, style = MaterialTheme.typography.bodyMedium)
                    }
                }
                Spacer(Modifier.height(12.dp))
            }
            TextButton(onCancel, Modifier.align(Alignment.CenterHorizontally)) {
                Text("Cancel", color = Color.White, style = MaterialTheme.typography.titleMedium)
            }
        }
    }
}

private fun DrawScope.drawFrame() {
    val side = size.width * 0.72f
    val topLeft = Offset((size.width - side) / 2, (size.height - side) / 2.2f)
    val arm = side * 0.16f
    val stroke = 6.dp.toPx()
    val corners = listOf(
        topLeft to Offset(1f, 1f), Offset(topLeft.x + side, topLeft.y) to Offset(-1f, 1f),
        Offset(topLeft.x, topLeft.y + side) to Offset(1f, -1f), Offset(topLeft.x + side, topLeft.y + side) to Offset(-1f, -1f),
    )
    for ((corner, dir) in corners) {
        drawLine(Color.White, corner, Offset(corner.x + arm * dir.x, corner.y), stroke, StrokeCap.Round)
        drawLine(Color.White, corner, Offset(corner.x, corner.y + arm * dir.y), stroke, StrokeCap.Round)
    }
}

/** For the previews only: a dim room and a laptop screen with a made-up QR code inside the frame. */
@Composable
private fun FakeCameraView() {
    Canvas(Modifier.fillMaxSize()) {
        drawRect(Brush.verticalGradient(listOf(Color(0xFF2B2F33), Color(0xFF15181B), Color(0xFF0C0E10))))
        val side = size.width * 0.62f
        val origin = Offset((size.width - side) / 2, (size.height - size.width * 0.72f) / 2.2f + size.width * 0.05f)
        drawRoundRect(Color(0xFF3A4048), Offset(origin.x - side * 0.25f, origin.y - side * 0.12f),
            Size(side * 1.5f, side * 1.22f), CornerRadius(18f))
        drawRect(Color(0xFFE8ECEF), origin, Size(side, side))
        val n = 41
        val cell = side * 0.9f / n
        val start = Offset(origin.x + side * 0.05f, origin.y + side * 0.05f)
        val random = Random(7)
        fun finder(cx: Int, cy: Int, x: Int, y: Int): Boolean? {
            val dx = x - cx
            val dy = y - cy
            if (dx !in -1..7 || dy !in -1..7) return null
            if (dx == -1 || dy == -1 || dx == 7 || dy == 7) return false
            val ring = minOf(dx, dy, 6 - dx, 6 - dy)
            return ring != 1
        }
        for (y in 0 until n) for (x in 0 until n) {
            val dark = finder(0, 0, x, y) ?: finder(n - 7, 0, x, y) ?: finder(0, n - 7, x, y) ?: (random.nextFloat() < 0.47f)
            if (dark) drawRect(Color(0xFF111416), Offset(start.x + x * cell, start.y + y * cell), Size(cell, cell))
        }
    }
}

/** After a good scan: the phone's name, which the server shows (`label`, §7), and where it will send. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NameScreen(
    label: String, storageHost: String, bucket: String, minutesLeft: Int,
    onLabel: (String) -> Unit = {}, onPair: () -> Unit = {}, onBack: () -> Unit = {},
) {
    Scaffold(topBar = {
        TopAppBar(title = { Text("Pair with your server") }, navigationIcon = {
            IconButton(onBack) { Icon(painterResource(R.drawable.ic_arrow_back), "Back") }
        })
    }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).padding(horizontal = 24.dp)) {
            Spacer(Modifier.height(8.dp))
            Text("Name this phone", style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(8.dp))
            Text(
                "Your server shows this name, so you can tell your phones apart.",
                style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(20.dp))
            OutlinedTextField(
                label, onLabel, Modifier.fillMaxWidth(), label = { Text("Name") }, singleLine = true,
                supportingText = { Text("Up to 40 characters") },
            )
            Spacer(Modifier.height(16.dp))
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
                Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
                    Text("From the QR code", style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 8.dp))
                    InfoRow(R.drawable.ic_cloud_upload, "Storage", storageHost)
                    InfoRow(R.drawable.ic_inventory_2, "Bucket", bucket)
                    InfoRow(R.drawable.ic_schedule, "The QR code is valid for", "$minutesLeft more minutes")
                }
            }
            Spacer(Modifier.weight(1f))
            Button(onPair, Modifier.fillMaxWidth().height(56.dp)) {
                Text("Pair", style = MaterialTheme.typography.titleMedium)
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

/** The fingerprint to compare with the server's (§7), while Sealdrop waits for the paired receipt. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CompareScreen(fingerprint: String, onStop: () -> Unit = {}) {
    Scaffold(topBar = { TopAppBar(title = { Text("Pair with your server") }) }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(horizontal = 24.dp)) {
            Spacer(Modifier.height(8.dp))
            Text("Compare this code", style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(8.dp))
            Text(
                "Your server shows a code too, as soon as it has this phone's request. Both must be the same. Then " +
                    "confirm on the server.",
                style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(24.dp))
            FingerprintBox(fingerprint)
            Spacer(Modifier.height(24.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 3.dp)
                Spacer(Modifier.width(16.dp))
                Column {
                    Text("Waiting for your server to confirm", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Sealdrop checks every 30 seconds. You can leave this screen: it keeps checking for up to 20 " +
                            "minutes.",
                        style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            Spacer(Modifier.height(28.dp))
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
                Column(Modifier.padding(16.dp)) {
                    Text("The codes are different?", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "Then someone else used the QR code first. Stop here, and on the server don't confirm. Make " +
                            "new storage keys for this phone, and pair again.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    OutlinedButton(onStop, Modifier.padding(top = 12.dp)) { Text("Stop pairing") }
                }
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

/** The paired receipt arrived. */
@Composable
fun PairedScreen(onDone: () -> Unit = {}) {
    Scaffold { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.weight(1f))
            Icon(
                painterResource(R.drawable.ic_check_circle), null, Modifier.size(96.dp),
                tint = SealdropTheme.extra.good,
            )
            Spacer(Modifier.height(16.dp))
            Text("Paired", style = MaterialTheme.typography.headlineMedium)
            Spacer(Modifier.height(8.dp))
            Text(
                "This phone now sends to your server, locked so that only your server can open it.",
                style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(32.dp))
            Card(
                Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
            ) {
                Column(Modifier.padding(16.dp)) {
                    Text("Next", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "Open the app that should send files. The first time it asks, Sealdrop shows its request, " +
                            "and you approve it once.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
            Spacer(Modifier.weight(1f))
            Button(onDone, Modifier.fillMaxWidth().height(56.dp)) { Text("Done", style = MaterialTheme.typography.titleMedium) }
            Spacer(Modifier.height(24.dp))
        }
    }
}

/** An app asks for the first time (§9.1): the owner compares its signing certificate and approves it once. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ApproveScreen(app: AppUi, certificateSha256: String, onApprove: () -> Unit = {}, onRefuse: () -> Unit = {}) {
    Scaffold(topBar = { TopAppBar(title = { Text("Approve an app") }) }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).padding(horizontal = 24.dp)) {
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                AppIcon(app, 56.dp)
                Spacer(Modifier.width(16.dp))
                Column {
                    Text(app.name, style = MaterialTheme.typography.headlineSmall)
                    Text(app.packageName, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            Spacer(Modifier.height(16.dp))
            Text(
                "wants to hand files to Sealdrop, to send them to your server.",
                style = MaterialTheme.typography.bodyLarge,
            )
            Spacer(Modifier.height(20.dp))
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
                Column(Modifier.fillMaxWidth().padding(16.dp)) {
                    Text("Its signing certificate (SHA-256)", style = MaterialTheme.typography.titleSmall)
                    Spacer(Modifier.height(8.dp))
                    for (line in certificateSha256.uppercase().chunked(16)) {
                        Text(groups(line), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleMedium)
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
            Text(
                "Approve it only if this is the certificate of your own build of the app. Sealdrop checks it on every " +
                    "call, so an app signed by anyone else can never use this approval.",
                style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.weight(1f))
            Button(onApprove, Modifier.fillMaxWidth().height(56.dp)) { Text("Approve", style = MaterialTheme.typography.titleMedium) }
            OutlinedButton(onRefuse, Modifier.fillMaxWidth().padding(top = 8.dp).height(56.dp)) {
                Text("Don't approve", style = MaterialTheme.typography.titleMedium)
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

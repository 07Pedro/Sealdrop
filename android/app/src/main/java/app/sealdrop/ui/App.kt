package app.sealdrop.ui

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import app.sealdrop.BuildConfig
import app.sealdrop.Engine
import app.sealdrop.core.Pairing
import app.sealdrop.net.Gate
import app.sealdrop.pair.Pairer
import app.sealdrop.send.Approvals
import app.sealdrop.send.Holds
import app.sealdrop.send.Owner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Where the owner is. Pairing and the approval of an app come first; otherwise the status screen. */
private sealed interface Route {
    data object Home : Route
    data class Scan(val error: String? = null) : Route
    data class Name(val offer: Pairing.Offer) : Route
    data object Compare : Route
    data object Paired : Route
    data object Settings : Route
}

/** The approved screens (docs/screens), with Sealdrop's state behind them. */
@Composable
fun SealdropApp(engine: Engine) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val changes by engine.changes.collectAsState()
    var route by remember { mutableStateOf<Route>(Route.Home) }
    var ticks by remember { mutableStateOf(0) }
    val snapshot by produceState<Snapshot?>(null, changes, route, ticks) { value = withContext(Dispatchers.IO) { Snapshot.of(engine) } }
    LaunchedEffect(Unit) {
        while (true) { // relative times ("5 minutes ago") and holds that run out
            delay(30_000)
            ticks++
        }
    }
    fun io(block: () -> Unit) = scope.launch { withContext(Dispatchers.IO) { block() } }
    val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}
    val s = snapshot ?: return

    when (val r = route) {
        is Route.Scan -> {
            BackHandler { route = Route.Home }
            ScanRoute(r.error, onCancel = { route = Route.Home }) { text ->
                try {
                    route = Route.Name(Pairer(engine).read(text))
                } catch (e: Pairer.Problem) {
                    route = Route.Scan(e.message)
                }
            }
        }
        is Route.Name -> {
            BackHandler { route = Route.Scan() }
            var label by remember { mutableStateOf(defaultLabel()) }
            NameScreen(
                label = label, storageHost = Gate.hostOf(r.offer.up.endpoint).name, bucket = r.offer.up.bucket,
                minutesLeft = maxOf(0, ((r.offer.expires - engine.clock() + 59_999) / 60_000).toInt()),
                onLabel = { label = it.take(60) }, onBack = { route = Route.Scan() },
                onPair = {
                    scope.launch {
                        val started = withContext(Dispatchers.IO) { runCatching { Pairer(engine).start(r.offer, label.trim()) } }
                        started.onSuccess { route = Route.Compare }
                        started.onFailure { Toast.makeText(context, it.message ?: "Pairing didn't start.", Toast.LENGTH_LONG).show() }
                    }
                },
            )
        }
        Route.Paired -> PairedScreen(onDone = {
            if (Build.VERSION.SDK_INT >= 33 &&
                ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
            ) notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
            route = Route.Home
        })
        Route.Settings -> {
            BackHandler { route = Route.Home }
            var unpairing by remember { mutableStateOf(false) }
            val status = s.status ?: return LaunchedEffect(Unit) { route = Route.Home }
            SettingsScreen(
                status, BuildConfig.VERSION_NAME,
                onWifiOnly = { on -> io { Owner.wifiOnly(engine, on) } },
                onWithdraw = { app -> io { Approvals.withdraw(engine, app.packageName) } },
                onPairAgain = { route = Route.Scan() },
                onUnpair = { unpairing = true },
                onBack = { route = Route.Home },
            )
            if (unpairing) {
                AlertDialog(
                    onDismissRequest = { unpairing = false },
                    title = { Text("Unpair this phone?") },
                    text = {
                        Text("Its keys are deleted, and so are the copies your server hasn't confirmed yet. The apps keep " +
                            "their own. Remove its storage keys at the storage provider too.")
                    },
                    confirmButton = {
                        TextButton({
                            unpairing = false
                            io { Pairer(engine).unpair() }
                            route = Route.Home
                        }) { Text("Unpair") }
                    },
                    dismissButton = { TextButton({ unpairing = false }) { Text("Cancel") } },
                )
            }
        }
        Route.Compare, Route.Home -> when {
            s.pending != null -> CompareRoute(engine, s.pending, onEnd = { route = it })
            route == Route.Compare -> LaunchedEffect(Unit) { route = Route.Home } // the pairing ended elsewhere
            s.request != null -> {
                val (app, request) = s.request
                ApproveScreen(
                    app, request.cert,
                    onApprove = { io { Approvals.approve(engine, request) } },
                    onRefuse = { io { Approvals.refuse(engine, request) } },
                )
            }
            s.status != null -> StatusScreen(
                s.status,
                onSettings = { route = Route.Settings },
                onSendNow = { engine.later.sendNow() },
                onEndHold = { hold -> io { Holds.release(engine, hold.packageName) } },
                onSendAgain = { f -> f.key?.let { (app, d) -> io { Owner.sendAgain(engine, app, d) } } },
                onDiscard = { f -> f.key?.let { (app, d) -> io { Owner.discard(engine, app, d) } } },
                onPairAgain = { route = Route.Scan() },
            )
            else -> WelcomeScreen(onScan = { route = Route.Scan() })
        }
    }
}

/** Waits for the paired receipt: checks every 30 seconds while shown (the background job does it otherwise). */
@Composable
private fun CompareRoute(engine: Engine, fingerprint: String, onEnd: (Route) -> Unit) {
    LaunchedEffect(fingerprint) {
        while (true) {
            when (withContext(Dispatchers.IO) { Pairer(engine).pollQuietly() }) {
                Pairer.Poll.PAIRED -> return@LaunchedEffect onEnd(Route.Paired)
                Pairer.Poll.EXPIRED -> return@LaunchedEffect onEnd(
                    Route.Scan("The QR code expired before your server confirmed. Start pairing again on your server."),
                )
                Pairer.Poll.NONE -> return@LaunchedEffect onEnd(Route.Home)
                Pairer.Poll.WAITING -> delay(Pairer.POLL_MS)
            }
        }
    }
    val scope = rememberCoroutineScope()
    CompareScreen(fingerprint.replace(" ", ""), onStop = {
        scope.launch {
            withContext(Dispatchers.IO) { Pairer(engine).stop() }
            onEnd(Route.Home)
        }
    })
}

/** The camera, once allowed ("only this time" is fine: it's needed only now). */
@Composable
private fun ScanRoute(error: String?, onCancel: () -> Unit, onText: (String) -> Unit) {
    val context = LocalContext.current
    var granted by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    var asked by remember { mutableStateOf(false) }
    val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        granted = it
        asked = true
    }
    LaunchedEffect(Unit) { if (!granted) ask.launch(Manifest.permission.CAMERA) }
    Box(Modifier.fillMaxSize()) {
        ScanScreen(
            error = error ?: if (!granted && asked) "Sealdrop needs the camera to read the QR code. Allow it, and try again." else null,
            onCancel = onCancel,
            camera = if (granted) ({ CameraPreview(onText) }) else null,
        )
    }
}

/** The phone's model, as the server shows it (`label`, §7); the owner can change it. */
private fun defaultLabel(): String = Build.MODEL.take(40).ifBlank { "Phone" }

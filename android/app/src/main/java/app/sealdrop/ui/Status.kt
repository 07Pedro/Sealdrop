package app.sealdrop.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import app.sealdrop.R
import app.sealdrop.ui.theme.SealdropTheme

/** The screen after pairing: is everything picked up, what needs a look, and what's waiting (§9.1, §9.3). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun StatusScreen(
    state: StatusUi,
    onSettings: () -> Unit = {}, onSendNow: () -> Unit = {}, onEndHold: (HoldUi) -> Unit = {},
    onSendAgain: (FailedUi) -> Unit = {}, onDiscard: (FailedUi) -> Unit = {}, onPairAgain: () -> Unit = {},
    scroll: ScrollState = rememberScrollState(),
) {
    Scaffold(topBar = {
        TopAppBar(
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    AppMark(28.dp)
                    Spacer(Modifier.width(12.dp))
                    Text("Sealdrop")
                }
            },
            actions = { IconButton(onSettings) { Icon(painterResource(R.drawable.ic_settings), "Settings") } },
        )
    }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).verticalScroll(scroll).padding(horizontal = 16.dp)) {
            Spacer(Modifier.height(8.dp))
            Summary(state)
            Spacer(Modifier.height(12.dp))
            for (w in state.warnings) {
                WarningCard(
                    w, action = if (w.kind == WarningKind.PAIR_AGAIN || w.kind == WarningKind.KEY_REFUSED) "Pair again" else null,
                    onAction = onPairAgain,
                )
            }
            if (state.holds.isNotEmpty()) Holds(state.holds, onEndHold)
            if (state.failed.isNotEmpty()) Failed(state.failed, onSendAgain, onDiscard)

            SectionTitle("Sending")
            InfoRow(R.drawable.ic_cloud_upload, "Last upload", state.lastUpload ?: "nothing sent yet")
            InfoRow(R.drawable.ic_dns, "Picked up by your server", state.lastPickup ?: "not yet")
            InfoRow(R.drawable.ic_verified_user, "Last backup on your server", state.lastBackup ?: "no backup reported")
            InfoRow(R.drawable.ic_hourglass_top, "Waiting on this phone", state.onPhone ?: "nothing")
            InfoRow(if (state.network.startsWith("Wi-Fi")) R.drawable.ic_wifi else R.drawable.ic_signal_cellular_alt,
                "Network", state.network)
            OutlinedButton(onSendNow, Modifier.padding(top = 4.dp)) {
                Icon(painterResource(R.drawable.ic_send), null, Modifier.size(ButtonDefaults.IconSize))
                Spacer(Modifier.width(ButtonDefaults.IconSpacing))
                Text("Send now")
            }

            SectionTitle("Apps")
            if (state.apps.isEmpty()) {
                Text("No app approved yet. When an app asks, Sealdrop shows its request.",
                    style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            for (app in state.apps) {
                ListItem(
                    headlineContent = { Text(app.name) },
                    supportingContent = { Text(app.note) },
                    leadingContent = { AppIcon(app) },
                    colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surface),
                )
            }

            SectionTitle("Your server")
            InfoRow(R.drawable.ic_lock, "Paired, code", groups(state.fingerprint))
            InfoRow(R.drawable.ic_smartphone, "This phone's name there", state.label)
            Spacer(Modifier.height(32.dp))
        }
    }
}

@Composable
private fun Summary(state: StatusUi) {
    val extra = SealdropTheme.extra
    val good = state.warnings.isEmpty() && state.failed.isEmpty()
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (good) extra.goodContainer else extra.warningContainer,
            contentColor = if (good) extra.onGoodContainer else extra.onWarningContainer,
        ),
    ) {
        Row(Modifier.padding(20.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(
                painterResource(if (good) R.drawable.ic_cloud_done else R.drawable.ic_pending), null, Modifier.size(40.dp),
            )
            Spacer(Modifier.width(16.dp))
            Column {
                Text(
                    when {
                        good && state.onPhone == null -> "All picked up"
                        good -> "Sending"
                        else -> "Needs a look"
                    },
                    style = MaterialTheme.typography.headlineSmall,
                )
                Text(
                    when {
                        good && state.lastPickup != null -> "Your server picked up the last upload ${state.lastPickup}."
                        good -> "Your server hasn't picked anything up yet."
                        // The cards below say what happened; this only points to them and reassures.
                        else -> "See below. Nothing is lost: everything waits on this phone until your server has it."
                    },
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}

@Composable
private fun Holds(holds: List<HoldUi>, onEndHold: (HoldUi) -> Unit) {
    Card(
        Modifier.fillMaxWidth().padding(bottom = 12.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(painterResource(R.drawable.ic_pause), null)
                Spacer(Modifier.width(12.dp))
                Text("Sending is on hold", style = MaterialTheme.typography.titleMedium)
            }
            Text(
                "An app asked Sealdrop to wait, for example while it records. The hold ends by itself.",
                style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 4.dp),
            )
            for (hold in holds) {
                Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text("${hold.app}, since ${hold.since}", Modifier.weight(1f), style = MaterialTheme.typography.bodyLarge)
                    TextButton({ onEndHold(hold) }) { Text("End hold") }
                }
            }
        }
    }
}

@Composable
private fun Failed(failed: List<FailedUi>, onSendAgain: (FailedUi) -> Unit, onDiscard: (FailedUi) -> Unit) {
    Card(
        Modifier.fillMaxWidth().padding(bottom = 12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer, contentColor = MaterialTheme.colorScheme.onErrorContainer,
        ),
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(painterResource(R.drawable.ic_error), null)
                Spacer(Modifier.width(12.dp))
                Text("Not delivered", style = MaterialTheme.typography.titleMedium)
            }
            Text(
                "Your server refused these twice. Sealdrop keeps them. Send them again once the app or the server is " +
                    "fixed, or discard them.",
                style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 4.dp),
            )
            for (f in failed) {
                HorizontalDivider(Modifier.padding(vertical = 12.dp), color = MaterialTheme.colorScheme.onErrorContainer.copy(alpha = 0.2f))
                Text("${f.app} · ${f.size} · ${f.since}", style = MaterialTheme.typography.bodyLarge)
                Text("Reason: ${f.reason}", style = MaterialTheme.typography.bodyMedium)
                Row(Modifier.padding(top = 8.dp)) {
                    Button({ onSendAgain(f) }) { Text("Send again") }
                    Spacer(Modifier.width(8.dp))
                    TextButton({ onDiscard(f) }) { Text("Discard", color = MaterialTheme.colorScheme.onErrorContainer) }
                }
            }
        }
    }
}

/** Settings: Wi-Fi only, the approved apps, pairing again or unpairing, and what Sealdrop talks to. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    state: StatusUi, version: String,
    onWifiOnly: (Boolean) -> Unit = {}, onWithdraw: (AppUi) -> Unit = {}, onPairAgain: () -> Unit = {},
    onUnpair: () -> Unit = {}, onBack: () -> Unit = {}, scroll: ScrollState = rememberScrollState(),
) {
    Scaffold(topBar = {
        TopAppBar(title = { Text("Settings") }, navigationIcon = {
            IconButton(onBack) { Icon(painterResource(R.drawable.ic_arrow_back), "Back") }
        })
    }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).verticalScroll(scroll)) {
            val items = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surface)
            ListItem(
                headlineContent = { Text("Wi-Fi only") },
                supportingContent = {
                    Text("Send everything on Wi-Fi only. Otherwise each app marks what may use mobile data: at most " +
                        "10 MB per run, never while roaming.")
                },
                trailingContent = { Switch(state.wifiOnly, onWifiOnly) },
                colors = items,
            )
            HorizontalDivider()
            SectionTitle("Approved apps", Modifier.padding(horizontal = 16.dp))
            for (app in state.apps) {
                ListItem(
                    headlineContent = { Text(app.name) },
                    supportingContent = { Text(app.packageName, fontFamily = FontFamily.Monospace) },
                    leadingContent = { AppIcon(app) },
                    trailingContent = { TextButton({ onWithdraw(app) }) { Text("Withdraw") } },
                    colors = items,
                )
            }
            HorizontalDivider()
            SectionTitle("Pairing", Modifier.padding(horizontal = 16.dp))
            ListItem(
                headlineContent = { Text("Pair again") },
                supportingContent = {
                    Text("With new storage keys, or after your server got new keys. Whatever isn't confirmed yet is " +
                        "sent again.")
                },
                leadingContent = { Icon(painterResource(R.drawable.ic_refresh), null) },
                trailingContent = { Icon(painterResource(R.drawable.ic_chevron_right), null) },
                colors = items,
                modifier = Modifier.clickable(onClick = onPairAgain),
            )
            ListItem(
                headlineContent = { Text("Unpair this phone", color = MaterialTheme.colorScheme.error) },
                supportingContent = {
                    Text("Deletes this phone's keys, and the copies your server hasn't confirmed yet. The apps keep " +
                        "their own.")
                },
                leadingContent = { Icon(painterResource(R.drawable.ic_link_off), null, tint = MaterialTheme.colorScheme.error) },
                colors = items,
                modifier = Modifier.clickable(onClick = onUnpair),
            )
            HorizontalDivider()
            SectionTitle("About", Modifier.padding(horizontal = 16.dp))
            ListItem(
                headlineContent = { Text("Sealdrop $version") },
                supportingContent = {
                    Text("Talks only to ${state.storageHost}, the storage from pairing. Open source: the format, the " +
                        "app and the server's collector are on GitHub, in 07Pedro/Sealdrop.")
                },
                leadingContent = { Icon(painterResource(R.drawable.ic_info), null) },
                colors = items,
            )
            Spacer(Modifier.height(32.dp))
        }
    }
}

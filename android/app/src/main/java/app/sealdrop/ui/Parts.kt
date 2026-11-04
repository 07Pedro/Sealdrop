package app.sealdrop.ui

import androidx.annotation.DrawableRes
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.requiredSize
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.painter.BitmapPainter
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import app.sealdrop.R
import app.sealdrop.ui.theme.SealdropTheme

/** The app's mark: the launcher icon's envelope and seal on its teal tile. */
@Composable
fun AppMark(size: Dp, modifier: Modifier = Modifier) {
    Box(
        modifier.size(size).clip(RoundedCornerShape(size * 0.28f)).background(Color(0xFF00696B)),
        contentAlignment = Alignment.Center,
    ) {
        // The drawing fills about 45 of the foreground's 108 units; scaled so it fills about 70 % of the tile.
        Image(painterResource(R.drawable.ic_launcher_foreground), null, Modifier.requiredSize(size * 1.69f))
    }
}

@Composable
fun AppIcon(app: AppUi, size: Dp = 40.dp) {
    if (app.icon != null) {
        Image(BitmapPainter(app.icon), null, Modifier.size(size).clip(RoundedCornerShape(size * 0.25f)))
    } else {
        Box(
            Modifier.size(size).clip(RoundedCornerShape(size * 0.25f)).background(MaterialTheme.colorScheme.secondaryContainer),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                app.name.take(1).uppercase(), color = MaterialTheme.colorScheme.onSecondaryContainer,
                style = if (size >= 48.dp) MaterialTheme.typography.headlineSmall else MaterialTheme.typography.titleMedium,
            )
        }
    }
}

@Composable
fun SectionTitle(text: String, modifier: Modifier = Modifier) {
    Text(
        text, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary,
        modifier = modifier.padding(top = 24.dp, bottom = 8.dp),
    )
}

/** A label and its value, with an icon: the status rows. */
@Composable
fun InfoRow(@DrawableRes icon: Int, label: String, value: String, valueColor: Color = Color.Unspecified) {
    Row(Modifier.fillMaxWidth().padding(vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(painterResource(icon), null, Modifier.size(24.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.width(16.dp))
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = MaterialTheme.typography.bodyLarge, color = valueColor)
        }
    }
}

/** A warning: amber, because nothing is lost and it only needs a look. */
@Composable
fun WarningCard(warning: WarningUi, action: String? = null, onAction: () -> Unit = {}) {
    val (title, body) = warningText(warning)
    val extra = SealdropTheme.extra
    Card(
        Modifier.fillMaxWidth().padding(bottom = 12.dp),
        colors = CardDefaults.cardColors(containerColor = extra.warningContainer, contentColor = extra.onWarningContainer),
    ) {
        Row(Modifier.padding(16.dp)) {
            Icon(painterResource(R.drawable.ic_warning), null, Modifier.size(24.dp))
            Spacer(Modifier.width(16.dp))
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.size(4.dp))
                Text(body, style = MaterialTheme.typography.bodyMedium)
                if (action != null) {
                    TextButton(onClick = onAction, Modifier.padding(top = 4.dp)) {
                        Text(action, color = extra.onWarningContainer, fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }
    }
}

/** The pairing fingerprint, large, in two lines of two groups (docs/PROTOCOL.md §7). */
@Composable
fun FingerprintBox(fingerprint: String, modifier: Modifier = Modifier) {
    val parts = groups(fingerprint).split(" ")
    Box(
        modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(MaterialTheme.colorScheme.primaryContainer)
            .padding(vertical = 28.dp),
        contentAlignment = Alignment.Center,
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
            for (line in parts.chunked(2)) {
                Text(
                    line.joinToString("  "), fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold,
                    style = MaterialTheme.typography.displaySmall, color = MaterialTheme.colorScheme.onPrimaryContainer,
                )
            }
        }
    }
}

/** A numbered step, for the welcome screen. */
@Composable
fun Step(number: Int, text: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = Alignment.Top) {
        Box(
            Modifier.size(28.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primary),
            contentAlignment = Alignment.Center,
        ) {
            Text("$number", color = MaterialTheme.colorScheme.onPrimary, style = MaterialTheme.typography.labelLarge)
        }
        Spacer(Modifier.width(16.dp))
        Text(text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(top = 2.dp))
    }
}

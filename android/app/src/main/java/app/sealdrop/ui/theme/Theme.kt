package app.sealdrop.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/** A calm teal, the same on every phone (no wallpaper colours: the screens should look as described). */
private val LightColors = lightColorScheme(
    primary = Color(0xFF00696B),
    onPrimary = Color.White,
    primaryContainer = Color(0xFF9CF1F2),
    onPrimaryContainer = Color(0xFF002020),
    secondary = Color(0xFF4A6363),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFCCE8E7),
    onSecondaryContainer = Color(0xFF051F1F),
    background = Color(0xFFF4FBFA),
    onBackground = Color(0xFF161D1D),
    surface = Color(0xFFF4FBFA),
    onSurface = Color(0xFF161D1D),
    surfaceVariant = Color(0xFFDAE5E4),
    onSurfaceVariant = Color(0xFF3F4948),
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color(0xFFEFF5F4),
    surfaceContainer = Color(0xFFE9EFEE),
    surfaceContainerHigh = Color(0xFFE3E9E9),
    surfaceContainerHighest = Color(0xFFDDE4E3),
    outline = Color(0xFF6F7979),
    outlineVariant = Color(0xFFBEC9C8),
    error = Color(0xFFBA1A1A),
    onError = Color.White,
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF80D4D5),
    onPrimary = Color(0xFF003738),
    primaryContainer = Color(0xFF004F51),
    onPrimaryContainer = Color(0xFF9CF1F2),
    secondary = Color(0xFFB0CCCB),
    onSecondary = Color(0xFF1B3435),
    secondaryContainer = Color(0xFF324B4B),
    onSecondaryContainer = Color(0xFFCCE8E7),
    background = Color(0xFF0E1515),
    onBackground = Color(0xFFDDE4E3),
    surface = Color(0xFF0E1515),
    onSurface = Color(0xFFDDE4E3),
    surfaceVariant = Color(0xFF3F4948),
    onSurfaceVariant = Color(0xFFBEC8C8),
    surfaceContainerLowest = Color(0xFF090F0F),
    surfaceContainerLow = Color(0xFF161D1D),
    surfaceContainer = Color(0xFF1A2121),
    surfaceContainerHigh = Color(0xFF252B2B),
    surfaceContainerHighest = Color(0xFF2F3636),
    outline = Color(0xFF889392),
    outlineVariant = Color(0xFF3F4948),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
)

/** What Material's scheme lacks: an amber for "needs a look, nothing is lost" and a green for "all done". */
@Immutable
data class ExtraColors(
    val warningContainer: Color,
    val onWarningContainer: Color,
    val warning: Color,
    val good: Color,
    val goodContainer: Color,
    val onGoodContainer: Color,
)

private val LightExtra = ExtraColors(
    warningContainer = Color(0xFFFFDDB3),
    onWarningContainer = Color(0xFF291800),
    warning = Color(0xFF825500),
    good = Color(0xFF2E6C35),
    goodContainer = Color(0xFFB0F2AF),
    onGoodContainer = Color(0xFF002106),
)

private val DarkExtra = ExtraColors(
    warningContainer = Color(0xFF633F00),
    onWarningContainer = Color(0xFFFFDDB3),
    warning = Color(0xFFFFB951),
    good = Color(0xFF95D594),
    goodContainer = Color(0xFF13521F),
    onGoodContainer = Color(0xFFB0F2AF),
)

val LocalExtraColors = staticCompositionLocalOf { LightExtra }

object SealdropTheme {
    val extra: ExtraColors
        @Composable get() = LocalExtraColors.current
}

@Composable
fun SealdropTheme(darkTheme: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    CompositionLocalProvider(LocalExtraColors provides if (darkTheme) DarkExtra else LightExtra) {
        MaterialTheme(colorScheme = if (darkTheme) DarkColors else LightColors, content = content)
    }
}

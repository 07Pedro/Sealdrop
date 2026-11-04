package app.sealdrop

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import app.sealdrop.ui.WelcomeScreen
import app.sealdrop.ui.theme.SealdropTheme

/** For now only the first screen: the screens are being agreed on (previews), the rest of the app comes after. */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent { SealdropTheme { WelcomeScreen() } }
    }
}

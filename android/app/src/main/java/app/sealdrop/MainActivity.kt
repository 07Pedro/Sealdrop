package app.sealdrop

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import app.sealdrop.ui.SealdropApp
import app.sealdrop.ui.theme.SealdropTheme
import kotlin.concurrent.thread

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val engine = Engine.get(this)
        thread { if (engine.paired() != null) engine.later.ensure() }
        setContent { SealdropTheme { SealdropApp(engine) } }
    }
}

package app.sealdrop.ui

import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import app.sealdrop.pair.Qr
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference

/**
 * The camera behind the scan screen: CameraX's preview, and every frame's brightness plane to the QR decoder. [onText]
 * gets each new text found (a refused one isn't given again); no image is kept.
 */
@Composable
fun CameraPreview(onText: (String) -> Unit) {
    val context = LocalContext.current
    val owner = LocalLifecycleOwner.current
    val last = remember { AtomicReference<String?>(null) }
    val analyzer = remember { Executors.newSingleThreadExecutor() }
    AndroidView(
        factory = { ctx ->
            val view = PreviewView(ctx)
            val future = ProcessCameraProvider.getInstance(ctx)
            future.addListener({
                val provider = future.get()
                val preview = Preview.Builder().build().also { it.setSurfaceProvider(view.surfaceProvider) }
                val analysis = ImageAnalysis.Builder().setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST).build()
                analysis.setAnalyzer(analyzer) { image ->
                    val plane = image.planes[0]
                    val text = try {
                        Qr.decodeLuma(plane.buffer, plane.rowStride, image.width, image.height)
                    } finally {
                        image.close()
                    }
                    if (text != null && last.getAndSet(text) != text) ContextCompat.getMainExecutor(ctx).execute { onText(text) }
                }
                provider.unbindAll()
                provider.bindToLifecycle(owner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
            }, ContextCompat.getMainExecutor(ctx))
            view
        },
        modifier = Modifier.fillMaxSize(),
    )
    DisposableEffect(Unit) {
        onDispose {
            ProcessCameraProvider.getInstance(context).addListener({
                ProcessCameraProvider.getInstance(context).get().unbindAll()
            }, ContextCompat.getMainExecutor(context))
            analyzer.shutdown()
        }
    }
}

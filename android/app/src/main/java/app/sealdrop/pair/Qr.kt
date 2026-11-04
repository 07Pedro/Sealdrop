package app.sealdrop.pair

import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.NotFoundException
import com.google.zxing.ChecksumException
import com.google.zxing.FormatException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader

/**
 * Reads the pairing QR code. Only ZXing's QR decoder, on the camera's brightness plane; light-on-dark too, since a
 * dark terminal shows the code inverted. Nothing of the image is kept.
 */
object Qr {
    private val hints = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        DecodeHintType.CHARACTER_SET to "UTF-8",
        DecodeHintType.TRY_HARDER to true,
        DecodeHintType.ALSO_INVERTED to true,
    )

    fun decode(source: LuminanceSource): String? = try {
        QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source)), hints).text
    } catch (e: NotFoundException) {
        null
    } catch (e: ChecksumException) {
        null
    } catch (e: FormatException) {
        null
    }

    /** The camera's Y plane ([width] × [height], rows [rowStride] bytes apart). */
    fun decodeLuma(plane: java.nio.ByteBuffer, rowStride: Int, width: Int, height: Int): String? {
        val data = ByteArray(width * height)
        val row = ByteArray(rowStride)
        plane.rewind()
        for (y in 0 until height) {
            val take = minOf(rowStride, plane.remaining())
            plane.get(row, 0, take)
            System.arraycopy(row, 0, data, y * width, minOf(width, take))
        }
        return decode(PlanarYUVLuminanceSource(data, width, height, 0, 0, width, height, false))
    }

    fun decode(bitmap: Bitmap): String? {
        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
        return decode(RGBLuminanceSource(bitmap.width, bitmap.height, pixels))
    }
}

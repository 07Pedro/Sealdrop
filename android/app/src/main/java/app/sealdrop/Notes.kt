package app.sealdrop

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.app.Notification

/** Sealdrop's one notification: an app asks to hand files over (§9.1). Everything else is on its screen. */
object Notes {
    private const val CHANNEL = "requests"
    private const val REQUEST = 1

    fun request(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, "App requests", NotificationManager.IMPORTANCE_DEFAULT).apply {
                description = "When an app asks to send files through Sealdrop"
            },
        )
        val open = PendingIntent.getActivity(
            context, 0, Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val note = Notification.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_launcher_monochrome)
            .setContentTitle("An app asks to send files")
            .setContentText("Open Sealdrop to compare its certificate and approve it.")
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        try {
            manager.notify(REQUEST, note)
        } catch (e: SecurityException) {
            // Notifications not allowed: the request shows when Sealdrop is opened.
        }
    }

    fun cancelRequest(context: Context) = context.getSystemService(NotificationManager::class.java).cancel(REQUEST)
}

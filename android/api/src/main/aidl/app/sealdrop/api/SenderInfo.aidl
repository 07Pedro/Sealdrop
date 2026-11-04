package app.sealdrop.api;

// waiting and oldestWaiting count the caller's own deliveries in states 1 to 3. maxDeliveryBytes: the most file bytes
// one delivery may hold. lostAt: when Sealdrop last found that the collector had lost deliveries of the caller; 0 if
// never. warnings: Sealdrop.WARNING_* bits.
parcelable SenderInfo {
    boolean paired; String fingerprint; long lastPickup; long lastBackup;
    int waiting; long oldestWaiting; int warnings; long maxDeliveryBytes; long lostAt;
}

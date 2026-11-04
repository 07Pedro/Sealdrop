package app.sealdrop.api;

// One file, opened read-only by the app: its path in the delivery, its size and its SHA-256 (hex).
parcelable FileOffer { String path; long size; String sha256; ParcelFileDescriptor file; }

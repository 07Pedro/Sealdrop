plugins {
    alias(libs.plugins.android.library)
}

// What an app needs to hand files to Sealdrop (docs/PROTOCOL.md §9.1): the AIDL interface, its parcelables and the
// numbers it answers with. Apps copy this module or depend on it.
android {
    namespace = "app.sealdrop.api"
    compileSdk = 37

    defaultConfig {
        minSdk = 37
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        aidl = true
    }
}

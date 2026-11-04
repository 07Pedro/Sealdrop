plugins {
    alias(libs.plugins.android.library)
}

// The format core (docs/PROTOCOL.md §2 to §7): sealing and opening files, manifests, receipts and pairing.
// Only the platform's crypto (Android 17: android.crypto.hpke and Conscrypt), no other library.
android {
    namespace = "app.sealdrop.core"
    compileSdk = 37

    defaultConfig {
        minSdk = 37
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // The shared test files (keys, sealed files, cases, vectors), read by the tests on the emulator.
    sourceSets {
        getByName("androidTest") {
            assets.directories.add("$rootDir/../testvectors")
        }
    }
}

dependencies {
    androidTestImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
}

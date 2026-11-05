import java.io.File
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.compose.compiler)
}

// The Sealdrop app (docs/PROTOCOL.md §9). Release builds are signed with the owner's own key, which is never in this
// repository: `sealdrop.signing` in local.properties names a keystore.properties file elsewhere (storeFile, relative to
// that file, storePassword, keyAlias, keyPassword). Without that line the release is left unsigned. Debug builds keep
// the debug key, for emulators and tests.
fun Properties.loadFrom(file: File) = apply { file.inputStream().use { load(it) } }

val signing: Properties? = rootProject.file("local.properties").takeIf { it.isFile }
    ?.let { Properties().loadFrom(it).getProperty("sealdrop.signing") }
    ?.let { path ->
        val file = File(path)
        check(file.isFile) { "local.properties names $path for signing, but it's missing. Restore it from the backup." }
        Properties().loadFrom(file).apply { setProperty("storeFile", File(file.parentFile, getProperty("storeFile")).path) }
    }

android {
    namespace = "app.sealdrop"
    compileSdk = 37

    defaultConfig {
        applicationId = "app.sealdrop"
        minSdk = 37
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (signing != null) create("owner") {
            storeFile = File(signing.getProperty("storeFile"))
            storePassword = signing.getProperty("storePassword")
            keyAlias = signing.getProperty("keyAlias")
            keyPassword = signing.getProperty("keyPassword")
        }
    }

    buildTypes {
        release {
            // Not shrunk: the release runs the same code the tests ran.
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("owner")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    // The JVM tests read the app's own sources (the "talks only to the storage" check).
    testOptions {
        unitTests.all { it.systemProperty("sealdrop.sources", "$projectDir/src/main/java") }
    }
}

dependencies {
    implementation(project(":core"))
    implementation(project(":api"))
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.material3)
    // The QR code: CameraX for the camera, ZXing's decoder only (no network, no other part of it).
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.zxing.core)
    debugImplementation(libs.androidx.compose.ui.test.manifest)

    testImplementation(libs.junit)

    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    // Espresso ≥ 3.7 is needed for touch injection on Android 17 (older versions call a removed API).
    androidTestImplementation(libs.androidx.test.espresso.core)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.junit)
}

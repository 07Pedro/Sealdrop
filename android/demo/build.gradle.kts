plugins {
    alias(libs.plugins.android.application)
}

// A made-up app that hands files to Sealdrop (docs/PROTOCOL.md §9.1): an example for app authors, and the sender in
// the end-to-end check (tools/e2e/). Plain views, no other library.
android {
    namespace = "org.example.sender"
    compileSdk = 37

    defaultConfig {
        applicationId = "org.example.sender"
        minSdk = 37
        targetSdk = 37
        versionCode = 1
        versionName = "1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":api"))

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.junit)
}

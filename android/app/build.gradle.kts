plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "ru.qdiver.client"
    compileSdk = 34

    defaultConfig {
        applicationId = "ru.qdiver.client"
        minSdk = 26
        targetSdk = 34
        versionCode = 2
        versionName = "0.2.0"
        // Ядро собрано под одну архитектуру: gomobile складывает .so внутрь .aar, и класть
        // рядом чужие abi незачем.
        ndk { abiFilters += "arm64-v8a" }
    }

    signingConfigs {
        // Ключ отладки лежит в репозитории намеренно: сменившаяся подпись означает, что
        // приложение больше не встанет поверх прежнего — только сносить, теряя настройки.
        getByName("debug") {
            storeFile = file("../debug.keystore")
            storePassword = "qdiver"
            keyAlias = "qdiver"
            keyPassword = "qdiver"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
        }
        debug {
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

dependencies {
    // Ядро: собирается командой gomobile bind в app/libs/qdiver.aar.
    implementation(files("libs/qdiver.aar"))

    implementation(platform(libs.compose.bom))
    implementation(libs.activity.compose)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons)
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.lifecycle.runtime)
}

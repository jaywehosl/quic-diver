pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // Ядро приезжает сюда файлом: gomobile собирает его сам, и версий у него нет —
        // оно всегда ровно то, что лежит в соседнем каталоге Go.
        flatDir { dirs("app/libs") }
    }
}

rootProject.name = "qdiver"
include(":app")

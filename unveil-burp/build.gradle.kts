plugins {
    java
}

group = "unveil"
version = "0.5.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("net.portswigger.burp.extensions:montoya-api:2023.8")
    implementation("com.google.code.gson:gson:2.10.1")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.jar {
    manifest {
        attributes(
            "Implementation-Title" to "Unveil",
            "Implementation-Version" to version,
            "Burp-Extension-Name" to "Unveil",
            "Burp-Extension-Expected-API-Version" to "2023.8"
        )
    }
    archiveBaseName.set("unveil-burp")
    // Include dependencies (e.g. Gson) so the extension loads; exclude Montoya (Burp provides it)
    val runtimeJars = configurations.runtimeClasspath.get().filter { f: java.io.File -> !f.name.contains("montoya") }
    from(runtimeJars.map { zipTree(it) }) {
        exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
    }
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}

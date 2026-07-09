plugins {
  id("uk.gov.justice.hmpps.gradle-spring-boot") version "10.5.7"
  kotlin("plugin.spring") version "2.4.0"
  kotlin("plugin.jpa") version "2.4.0"
}

configurations {
  testImplementation { exclude(group = "org.junit.vintage") }
}

dependencies {
  implementation("org.springframework.boot:spring-boot-starter-data-jpa")
  implementation("org.springframework.boot:spring-boot-starter-oauth2-client")
  implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")
  implementation("org.springframework.boot:spring-boot-starter-security")
  implementation("org.springframework.boot:spring-boot-starter-web")
  implementation("org.springframework.boot:spring-boot-starter-webflux")
  implementation("org.springframework.boot:spring-boot-starter-flyway")
  implementation("org.springframework.security:spring-security-oauth2-authorization-server")
  implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
  implementation("org.flywaydb:flyway-core")
  // Temporarily pin spring doc at 3.0.2 whilst waiting for 3.0.4 upgrade
  val springDocVersion = "3.0.2"
  implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:$springDocVersion")
  constraints {
    implementation("org.webjars:swagger-ui:5.32.2")
  }
  implementation("org.json:json:20260522")
  implementation("commons-codec:commons-codec")
  implementation("org.apache.commons:commons-text:1.15.0")
  implementation("io.opentelemetry:opentelemetry-api")
  implementation("io.jsonwebtoken:jjwt:0.13.0")
  implementation("commons-logging:commons-logging:1.4.0")

  runtimeOnly("com.h2database:h2:2.4.240")
  runtimeOnly("org.postgresql:postgresql:42.7.13")
  runtimeOnly("org.flywaydb:flyway-database-postgresql")

  testImplementation("org.springframework.boot:spring-boot-webtestclient")
  testImplementation("org.springframework.boot:spring-boot-starter-webflux")
  testImplementation("io.jsonwebtoken:jjwt-impl:0.13.0")
  testImplementation("io.jsonwebtoken:jjwt-jackson:0.13.0")
  implementation(kotlin("stdlib"))
}

java {
  toolchain.languageVersion.set(JavaLanguageVersion.of(25))
}

tasks {
  withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    compilerOptions.jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_25
  }
}

package uk.gov.justice.digital.hmpps.authorizationapi.data.model

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import java.time.LocalDateTime

class ClientTest {

  @Test
  fun shouldUseLastAccessedDateTimeWhenPresent() {
    val tenDaysAgo = LocalDateTime.now().minusDays(10)
    val twoDaysAgo = LocalDateTime.now().minusDays(2)

    val clientOAuth2 = givenClientOAuth2With(
      lastAccessedDate = twoDaysAgo,
      clientIdIssuedAt = tenDaysAgo,
    )

    assertThat(clientOAuth2.getLastActiveDate()).isEqualTo(twoDaysAgo)
  }

  @Test
  fun shouldUseClientIdIssuedAtDateTimeWhenNoActivityOnClientSinceCreation() {
    val tenDaysAgo = LocalDateTime.now().minusDays(10)

    val clientOAuth2 = givenClientOAuth2With(
      lastAccessedDate = null,
      clientIdIssuedAt = tenDaysAgo,
    )

    assertThat(clientOAuth2.getLastActiveDate()).isEqualTo(tenDaysAgo)
  }

  private fun givenClientOAuth2With(
    lastAccessedDate: LocalDateTime?,
    clientIdIssuedAt: LocalDateTime,
  ): Client = Client(
    id = "1234",
    clientId = "clientId",
    clientIdIssuedAt = clientIdIssuedAt,
    clientSecret = "clientSecret",
    clientSecretExpiresAt = LocalDateTime.now(),
    clientName = "clientName",
    clientAuthenticationMethods = "clientAuthenticationMethods",
    authorizationGrantTypes = "authorizationGrantTypes",
    redirectUris = "redirectUris",
    postLogoutRedirectUris = null,
    scopes = emptyList(),
    clientSettings = ClientSettings.withSettings(mutableMapOf("clientId" to "clientId", "clientSecret" to "clientSecret") as Map<String, Any>).build(),
    tokenSettings = TokenSettings.withSettings(mutableMapOf("clientId" to "clientId", "clientSecret" to "clientSecret") as Map<String, Any>).build(),
    lastAccessedDate = lastAccessedDate,
    mfaRememberMe = false,
    mfa = null,
    skipToAzure = false,
    resourceIds = emptyList(),
  )
}

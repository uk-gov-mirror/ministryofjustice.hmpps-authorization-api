package uk.gov.justice.digital.hmpps.authorizationapi.integration

import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.transaction.annotation.Transactional
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.AuthorizationRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.service.JpaOAuth2AuthorizationService
import java.time.LocalDateTime
import java.time.ZoneId
import java.util.UUID

@Transactional
class JpaOAuth2AuthorizationServiceIntTest : IntegrationTestBase() {

  @Autowired
  private lateinit var authorizationRepository: AuthorizationRepository

  @Autowired
  private lateinit var registeredClientRepository: JdbcRegisteredClientRepository

  private lateinit var authorizationService: OAuth2AuthorizationService

  @BeforeEach
  fun setUp() {
    authorizationService = JpaOAuth2AuthorizationService(authorizationRepository, registeredClientRepository)
  }

  @Test
  fun shouldManageAuthorizations() {
    val oAuth2Authorization = createOAuth2Authorization()
    authorizationService.save(oAuth2Authorization)

    val retrieved = authorizationService.findById(oAuth2Authorization.id)
    assertNotNull(retrieved)
    assertTrue(oAuth2Authorization == retrieved)

    val retrievedByToken = authorizationService.findByToken("1234-test-access-token-1234", OAuth2TokenType.ACCESS_TOKEN)
    assertNull(retrievedByToken)

    val retrievedByAuthorizationCode = authorizationService.findByToken("1234-test-authorization-code-1234", OAuth2TokenType(OAuth2ParameterNames.CODE))
    assertNotNull(retrievedByAuthorizationCode)
    assertTrue(oAuth2Authorization == retrievedByAuthorizationCode)

    authorizationService.remove(retrievedByAuthorizationCode!!)
    val removed = authorizationService.findById(oAuth2Authorization.id)
    assertNull(removed)
  }

  private fun createOAuth2Authorization(): OAuth2Authorization {
    val registeredClient = registeredClientRepository.findByClientId("test-auth-code-client")
    val authorizationId = UUID.randomUUID().toString()

    val authorizationCode = OAuth2AuthorizationCode(
      "1234-test-authorization-code-1234",
      LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant(),
      LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant(),
    )

    return OAuth2Authorization.withRegisteredClient(registeredClient!!)
      .id(authorizationId)
      .principalName("testy")
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizedScopes(setOf("read", "write"))
      .attributes { attributes -> attributes.putAll(mapOf("attrib1" to "attrib1-value", "attrib2" to "attrib2-value")) }
      .token(authorizationCode) { metadata -> metadata.putAll(mapOf("metadata1" to "metadata1-value")) }
      .build()
  }
}

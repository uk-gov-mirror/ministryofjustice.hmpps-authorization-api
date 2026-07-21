package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException
import java.util.function.Consumer

class LoggingRedirectUriValidator(private val delegate: Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext>) : Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {

  companion object {
    private val log = LoggerFactory.getLogger(this::class.java)
  }

  override fun accept(t: OAuth2AuthorizationCodeRequestAuthenticationContext) {
    try {
      delegate.accept(t)
    } catch (e: OAuth2AuthorizationCodeRequestAuthenticationException) {
      if (e.error.description != null && e.error.description?.contains("redirect_uri") == true) {
        log.info("redirect_uri error: ${e.error}")
      }

      throw e
    }
  }
}

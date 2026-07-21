package uk.gov.justice.digital.hmpps.authorizationapi.service

import org.apache.commons.lang3.StringUtils
import org.apache.commons.lang3.StringUtils.isBlank
import org.apache.commons.lang3.StringUtils.isNotEmpty
import org.springframework.data.repository.findByIdOrNull
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.JwtClaimNames
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.stereotype.Component
import uk.gov.justice.digital.hmpps.authorizationapi.data.model.AuthorizationConsent
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.AuthorizationConsentRepository
import uk.gov.justice.digital.hmpps.authorizationapi.data.repository.UserAuthorizationCodeRepository
import uk.gov.justice.digital.hmpps.authorizationapi.service.AuthSource.Companion.fromNullableString
import uk.gov.justice.digital.hmpps.authorizationapi.utils.OAuthJtiGenerator
import java.util.stream.Collectors

@Component
class TokenCustomizer(
  private val authorizationConsentRepository: AuthorizationConsentRepository,
  private val userAuthorizationCodeRepository: UserAuthorizationCodeRepository,
  private val registeredClientAdditionalInformation: RegisteredClientAdditionalInformation,
  private val oauthJtiGenerator: OAuthJtiGenerator,
) : OAuth2TokenCustomizer<JwtEncodingContext> {

  companion object {
    private const val REQUEST_PARAM_USER_NAME = "username"
    private const val REQUEST_PARAM_AUTH_SOURCE = "auth_source"
    private const val ADD_INFO_AUTH_SOURCE = "auth_source"
    private const val ADD_INFO_NAME = "name"
    private const val ADD_INFO_USER_NAME = "user_name"
    private const val ADD_INFO_USER_ID = "user_id"
    private const val ADD_INFO_USER_UUID = "user_uuid"
    private const val SUBJECT = "sub"
    private const val JWT_ID = "jwt_id"
  }

  override fun customize(context: JwtEncodingContext) {
    context.let { jwtEncodingContext ->
      suppressAudienceClaim(jwtEncodingContext)

      if (jwtEncodingContext.getPrincipal<Authentication>() is OAuth2ClientAuthenticationToken) {
        val principal = jwtEncodingContext.getPrincipal<Authentication>() as OAuth2ClientAuthenticationToken
        addClientAuthorities(jwtEncodingContext, principal)
        customizeClientCredentials(jwtEncodingContext, principal)
      } else if (jwtEncodingContext.getPrincipal<Authentication>() is UsernamePasswordAuthenticationToken) {
        addUserClaims(jwtEncodingContext, jwtEncodingContext.getPrincipal<Authentication>() as UsernamePasswordAuthenticationToken)
        val additionalInfo: MutableMap<String, Any> = mutableMapOf()
        context.authorization?.let {
          userAuthorizationCodeRepository.findByIdOrNull(it.id)?.let { userAuthorizationCode ->
            additionalInfo[ADD_INFO_USER_ID] = userAuthorizationCode.userId
            additionalInfo[ADD_INFO_NAME] = userAuthorizationCode.name
            additionalInfo[ADD_INFO_USER_NAME] = userAuthorizationCode.username
            additionalInfo[SUBJECT] = userAuthorizationCode.username
            additionalInfo[ADD_INFO_USER_UUID] = userAuthorizationCode.userUuid.toString()
            additionalInfo[ADD_INFO_AUTH_SOURCE] = StringUtils.defaultIfBlank(userAuthorizationCode.authSource.name.lowercase(), "none")
            additionalInfo[JWT_ID] = userAuthorizationCode.jwtId
          }
        }
        filterJwtFields(additionalInfo, context)
      }
    }
  }

  private fun filterJwtFields(info: Map<String, Any>, context: JwtEncodingContext) {
    val jwtFields = registeredClientAdditionalInformation.getJwtFields(context.registeredClient.clientSettings)
    val entries = if (isBlank(jwtFields)) {
      emptySet()
    } else {
      jwtFields!!.split(",")
    }
    info.entries.filterNot { entries.contains(it.key) }.map { context.claims.claim(it.key, it.value) }
  }

  private fun addUserClaims(context: JwtEncodingContext, principal: UsernamePasswordAuthenticationToken) {
    addAuthorities(context, principal.authorities)

    with(context.claims) {
      claim("client_id", context.registeredClient.clientId)
      claim("grant_type", GrantType.authorization_code)
      claim("scope", context.registeredClient.scopes)
    }
  }

  private fun addClientAuthorities(context: JwtEncodingContext, principal: OAuth2ClientAuthenticationToken) {
    principal.registeredClient?.let { registeredClient ->
      val oAuth2AuthorizationConsent = authorizationConsentRepository.findByIdOrNull(AuthorizationConsent.AuthorizationConsentId(registeredClient.id, registeredClient.clientId))

      oAuth2AuthorizationConsent?.let { consent ->
        addAuthorities(context, consent.authorities.map { SimpleGrantedAuthority(it) })
      }
    }
  }

  private fun addAuthorities(context: JwtEncodingContext, grantedAuthorities: Collection<GrantedAuthority>) {
    val authorities = grantedAuthorities.stream().map { obj: GrantedAuthority -> obj.authority }
      .collect(Collectors.toSet())
    context.claims.claim("authorities", authorities)
  }
  private fun customizeClientCredentials(context: JwtEncodingContext, principal: OAuth2ClientAuthenticationToken) {
    with(context.claims) {
      val token: OAuth2ClientCredentialsAuthenticationToken? = context.getAuthorizationGrant()
      token?.let {
        if (it.additionalParameters.containsKey(REQUEST_PARAM_USER_NAME) && isNotEmpty(token.additionalParameters[REQUEST_PARAM_USER_NAME] as String)) {
          claim("user_name", it.additionalParameters[REQUEST_PARAM_USER_NAME]!!)
          claim("sub", it.additionalParameters[REQUEST_PARAM_USER_NAME]!!)
        }

        claim("auth_source", fromNullableString(it.additionalParameters[REQUEST_PARAM_AUTH_SOURCE] as String?).source)
        registeredClientAdditionalInformation.getDatabaseUserName(principal.registeredClient?.clientSettings)?.let { databaseUsername ->
          if (!isBlank(databaseUsername)) {
            claim("database_username", databaseUsername)
          }
        }
      }

      claim("client_id", principal.registeredClient?.clientId ?: "Unknown")
      claim("scope", principal.registeredClient?.scopes ?: emptySet<String>())
      claim("grant_type", context.authorizationGrantType?.value ?: "Unknown")
      claim("jti", oauthJtiGenerator.generateTokenId())
    }
  }

  private fun suppressAudienceClaim(context: JwtEncodingContext) {
    context.claims.claims { claims -> claims.remove(JwtClaimNames.AUD) }
  }
}

@Suppress("ktlint:standard:enum-entry-name-case")
enum class GrantType {
  client_credentials,
  authorization_code,
}

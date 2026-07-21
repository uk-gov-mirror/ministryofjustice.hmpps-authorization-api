package uk.gov.justice.digital.hmpps.authorizationapi.service

import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpHeaders
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.util.StringUtils
import java.nio.charset.StandardCharsets
import java.util.Base64

class ClientSecretBasicBase64OnlyAuthenticationConverter : AuthenticationConverter {

  override fun convert(request: HttpServletRequest): Authentication? {
    val header = request.getHeader(HttpHeaders.AUTHORIZATION) ?: return null

    val parts = header.split("\\s".toRegex()).toTypedArray()
    if (!parts[0].equals("Basic", ignoreCase = true)) {
      return null
    }

    if (parts.size != 2) {
      throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST)
    }

    val decodedCredentials: ByteArray = try {
      Base64.getDecoder().decode(parts[1].toByteArray(StandardCharsets.UTF_8))
    } catch (ex: IllegalArgumentException) {
      throw OAuth2AuthenticationException(OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), ex)
    }

    val credentialsString = String(decodedCredentials, StandardCharsets.UTF_8)
    val credentials = credentialsString.split(":".toRegex(), 2).toTypedArray()
    if (credentials.size != 2 ||
      !StringUtils.hasText(credentials[0]) ||
      !StringUtils.hasText(
        credentials[1],
      )
    ) {
      throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST)
    }

    return OAuth2ClientAuthenticationToken(
      credentials[0],
      ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
      credentials[1],
      getParametersIfMatchesAuthorizationCodeGrantRequest(request),
    )
  }

  private fun getParametersIfMatchesAuthorizationCodeGrantRequest(
    request: HttpServletRequest,
    vararg exclusions: String,
  ): Map<String, Any> {
    if (!matchesAuthorizationCodeGrantRequest(request)) {
      return emptyMap()
    }
    val multiValueParameters =
      if ("GET" == request.method) {
        getQueryParameters(request)
      } else {
        getFormParameters(
          request,
        )
      }
    for (exclusion in exclusions) {
      multiValueParameters.remove(exclusion)
    }
    val parameters: MutableMap<String, Any> = HashMap()
    multiValueParameters.forEach { (key: String, value: List<String>) ->
      parameters[key] = if (value.size == 1) value[0] else value.toTypedArray()
    }
    return parameters
  }

  private fun matchesAuthorizationCodeGrantRequest(request: HttpServletRequest): Boolean = (
    AuthorizationGrantType.AUTHORIZATION_CODE.value
      == request.getParameter(OAuth2ParameterNames.GRANT_TYPE)
    ) &&
    request.getParameter(OAuth2ParameterNames.CODE) != null

  private fun getQueryParameters(request: HttpServletRequest): MultiValueMap<String, String> {
    val parameterMap = request.parameterMap
    val parameters: MultiValueMap<String, String> = LinkedMultiValueMap()
    parameterMap.forEach { (key: String, values: Array<String>) ->
      val queryString =
        if (StringUtils.hasText(request.queryString)) request.queryString else ""
      if (queryString.contains(key) && values.isNotEmpty()) {
        for (value in values) {
          parameters.add(key, value)
        }
      }
    }
    return parameters
  }

  private fun getFormParameters(request: HttpServletRequest): MultiValueMap<String, String> {
    val parameterMap = request.parameterMap
    val parameters: MultiValueMap<String, String> = LinkedMultiValueMap()
    parameterMap.forEach { (key: String, values: Array<String>) ->
      val queryString =
        if (StringUtils.hasText(request.queryString)) request.queryString else ""
      // If not query parameter then it's a form parameter
      if (!queryString.contains(key) && values.isNotEmpty()) {
        for (value in values) {
          parameters.add(key, value)
        }
      }
    }
    return parameters
  }
}

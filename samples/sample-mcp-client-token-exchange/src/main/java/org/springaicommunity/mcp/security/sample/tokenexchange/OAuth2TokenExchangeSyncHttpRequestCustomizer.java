/*
 * Copyright 2026-2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springaicommunity.mcp.security.sample.tokenexchange;

import java.net.URI;
import java.net.http.HttpRequest;

import io.modelcontextprotocol.client.transport.customizer.McpSyncHttpClientRequestCustomizer;
import io.modelcontextprotocol.common.McpTransportContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.TokenExchangeOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.RestClientTokenExchangeTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Adds an OAuth2 access token to outgoing MCP client HTTP requests using the
 * <a href="https://www.rfc-editor.org/rfc/rfc8693">RFC 8693 token exchange</a> grant
 * type.
 * <p>
 * This customizer is intended for MCP hosts that are OAuth2 resource servers, for example
 * a backend service sitting behind a gateway: the user authenticates elsewhere, and the
 * host only holds a validated user token whose audience is not the MCP server. That token
 * cannot be passed through to the MCP server directly, as the MCP authorization
 * specification requires audience validation and forbids token passthrough.
 * <p>
 * The user {@link Authentication} is read from the {@link McpTransportContext} (see
 * {@link AuthenticationMcpTransportContextProvider}) and used as the principal of the
 * {@link OAuth2AuthorizeRequest}, so the user's token is sent as the
 * {@code subject_token} and exchanged for a token whose audience is the MCP server,
 * preserving the user's identity.
 * <p>
 * The {@link OAuth2AuthorizedClientManager} must be configured with a
 * {@link TokenExchangeOAuth2AuthorizedClientProvider}. Use
 * {@link #tokenExchangeAuthorizedClientManager(ClientRegistrationRepository, OAuth2AuthorizedClientService)}
 * for a manager that sends a {@code subject_token_type} accepted by both Keycloak and
 * Spring Authorization Server.
 * <p>
 * When no user {@link Authentication} is present in the transport context (for example
 * for requests sent on application startup or from background threads), no
 * {@code Authorization} header is added. Use
 * {@link #failOnMissingAuthentication(boolean)} to throw instead, for multi-tenant setups
 * where user-scoped requests must never be sent without the user's identity.
 * <p>
 * The resolved access token is added as a {@code Bearer} token in the
 * {@code Authorization} header of each outgoing MCP request.
 *
 * @author Yeongchan Shin
 * @see TokenExchangeOAuth2AuthorizedClientProvider
 */
public class OAuth2TokenExchangeSyncHttpRequestCustomizer implements McpSyncHttpClientRequestCustomizer {

	private static final Logger log = LoggerFactory.getLogger(OAuth2TokenExchangeSyncHttpRequestCustomizer.class);

	private static final String ACCESS_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:access_token";

	private final OAuth2AuthorizedClientManager authorizedClientManager;

	private final String clientRegistrationId;

	private boolean failOnMissingAuthentication = false;

	public OAuth2TokenExchangeSyncHttpRequestCustomizer(OAuth2AuthorizedClientManager authorizedClientManager,
			String clientRegistrationId) {
		this.authorizedClientManager = authorizedClientManager;
		this.clientRegistrationId = clientRegistrationId;
	}

	@Override
	public void customize(HttpRequest.Builder builder, String method, URI endpoint, String body,
			McpTransportContext context) {
		if (!(context.get(
				AuthenticationMcpTransportContextProvider.AUTHENTICATION_KEY) instanceof Authentication authentication)) {
			if (this.failOnMissingAuthentication) {
				throw new IllegalStateException("No user authentication available for token exchange with client ["
						+ this.clientRegistrationId + "]");
			}
			log.debug("No authentication found: not requesting token");
			return;
		}

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
			.withClientRegistrationId(this.clientRegistrationId)
			.principal(authentication)
			.build();
		log.debug("Requesting access token for client [{}]", this.clientRegistrationId);
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest);
		if (authorizedClient == null) {
			throw new IllegalArgumentException(
					"Authorization not supported for client [" + this.clientRegistrationId + "]");
		}
		OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
		log.debug("Obtained access token");
		builder.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue());
	}

	/**
	 * Fail when no user {@link Authentication} is present in the transport context,
	 * instead of sending the request without an {@code Authorization} header. Set to
	 * {@code true} in multi-tenant setups where sending a user-scoped request without the
	 * user's identity must be avoided.
	 * @param failOnMissingAuthentication whether to fail on missing authentication
	 */
	public void failOnMissingAuthentication(boolean failOnMissingAuthentication) {
		this.failOnMissingAuthentication = failOnMissingAuthentication;
	}

	/**
	 * Creates an {@link OAuth2AuthorizedClientManager} configured for token exchange,
	 * sending the subject token as {@code urn:ietf:params:oauth:token-type:access_token}.
	 * <p>
	 * That is the type <a href="https://www.rfc-editor.org/rfc/rfc8693#section-3">RFC
	 * 8693 section 3</a> defines for an access token issued by the authorization server
	 * being called, which is what a resource-server host holds; the {@code ...:jwt} type
	 * is defined for sending a JWT as an authorization grant to a <em>different</em>
	 * authorization server (RFC 7523).
	 * <p>
	 * Spring Security's default resolver derives {@code subject_token_type} from the Java
	 * type of the subject token, so a {@link Jwt} principal is sent as {@code ...:jwt}.
	 * Spring Authorization Server accepts both types, while Keycloak's standard token
	 * exchange accepts access tokens only, so the type is set explicitly here.
	 * @param clientRegistrationRepository the client registration repository
	 * @param authorizedClientService the authorized client service
	 * @return an authorized client manager supporting the token exchange grant
	 */
	public static OAuth2AuthorizedClientManager tokenExchangeAuthorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientService authorizedClientService) {
		var accessTokenResponseClient = new RestClientTokenExchangeTokenResponseClient();
		accessTokenResponseClient.setParametersCustomizer(
				(parameters) -> parameters.set(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, ACCESS_TOKEN_TYPE_VALUE));

		var provider = new TokenExchangeOAuth2AuthorizedClientProvider();
		provider.setAccessTokenResponseClient(accessTokenResponseClient);

		var manager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository,
				authorizedClientService);
		manager.setAuthorizedClientProvider(provider);
		return manager;
	}

}

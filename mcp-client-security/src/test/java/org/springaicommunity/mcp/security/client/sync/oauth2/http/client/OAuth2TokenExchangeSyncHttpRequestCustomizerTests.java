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

package org.springaicommunity.mcp.security.client.sync.oauth2.http.client;

import java.net.URI;
import java.net.http.HttpRequest;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

import io.modelcontextprotocol.common.McpTransportContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OAuth2TokenExchangeSyncHttpRequestCustomizer}.
 *
 * @author Yeongchan Shin
 */
class OAuth2TokenExchangeSyncHttpRequestCustomizerTests {

	private static final String REGISTRATION_ID = "test-registration";

	private static final String TOKEN_VALUE = "test-access-token";

	private static final URI ENDPOINT = URI.create("https://mcp.example.com");

	private static final Authentication AUTHENTICATION = new TestingAuthenticationToken("user", "password");

	private final OAuth2AuthorizedClientManager authorizedClientManager = mock(OAuth2AuthorizedClientManager.class);

	private final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(ENDPOINT);

	private OAuth2TokenExchangeSyncHttpRequestCustomizer customizer;

	@BeforeEach
	void setUp() {
		this.customizer = new OAuth2TokenExchangeSyncHttpRequestCustomizer(this.authorizedClientManager,
				REGISTRATION_ID);
	}

	@Test
	@DisplayName("Adds Bearer token to Authorization header")
	void addsBearerToken() {
		given(authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(authorizedClient(clientRegistration()));

		customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", contextWithAuthentication());

		assertThat(requestBuilder.build().headers().firstValue(HttpHeaders.AUTHORIZATION))
			.hasValue("Bearer " + TOKEN_VALUE);
	}

	@Test
	@DisplayName("Uses the user authentication as the authorize request principal")
	void usesAuthenticationAsPrincipal() {
		given(authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(authorizedClient(clientRegistration()));

		customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", contextWithAuthentication());

		var authorizeRequestCaptor = ArgumentCaptor.forClass(OAuth2AuthorizeRequest.class);
		then(authorizedClientManager).should().authorize(authorizeRequestCaptor.capture());
		assertThat(authorizeRequestCaptor.getValue().getClientRegistrationId()).isEqualTo(REGISTRATION_ID);
		assertThat(authorizeRequestCaptor.getValue().getPrincipal()).isEqualTo(AUTHENTICATION);
	}

	@Test
	@DisplayName("Throws IllegalArgumentException when authorizedClientManager returns null")
	void authorizedClientManagerReturnsNull() {
		given(authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class))).willReturn(null);

		assertThatIllegalArgumentException()
			.isThrownBy(() -> customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", contextWithAuthentication()))
			.withMessageContaining(REGISTRATION_ID);
	}

	@Nested
	@DisplayName("Does not add authorization header")
	class NoAuthorization {

		@Test
		@DisplayName("when context is empty")
		void emptyContext() {
			customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", McpTransportContext.EMPTY);

			assertThat(requestBuilder.build().headers().map()).doesNotContainKey(HttpHeaders.AUTHORIZATION);
			verifyNoInteractions(authorizedClientManager);
		}

		@Test
		@DisplayName("when authentication key is not an Authentication instance")
		void contextWithNonAuthenticationValue() {
			var context = McpTransportContext
				.create(Map.of(AuthenticationMcpTransportContextProvider.AUTHENTICATION_KEY, "not-an-authentication"));

			customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", context);

			assertThat(requestBuilder.build().headers().map()).doesNotContainKey(HttpHeaders.AUTHORIZATION);
			verifyNoInteractions(authorizedClientManager);
		}

	}

	@Nested
	@DisplayName("Fail on missing authentication")
	class FailOnMissingAuthentication {

		@Test
		@DisplayName("when enabled and context is empty, throws")
		void enabledAndEmptyContext() {
			customizer.failOnMissingAuthentication(true);

			assertThatIllegalStateException()
				.isThrownBy(
						() -> customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", McpTransportContext.EMPTY))
				.withMessageContaining(REGISTRATION_ID);
			verifyNoInteractions(authorizedClientManager);
		}

		@Test
		@DisplayName("when enabled and authentication is present, adds Bearer token")
		void enabledAndAuthenticationPresent() {
			customizer.failOnMissingAuthentication(true);
			given(authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
				.willReturn(authorizedClient(clientRegistration()));

			customizer.customize(requestBuilder, "POST", ENDPOINT, "{}", contextWithAuthentication());

			assertThat(requestBuilder.build().headers().firstValue(HttpHeaders.AUTHORIZATION))
				.hasValue("Bearer " + TOKEN_VALUE);
		}

	}

	private static McpTransportContext contextWithAuthentication() {
		return McpTransportContext
			.create(Map.of(AuthenticationMcpTransportContextProvider.AUTHENTICATION_KEY, AUTHENTICATION));
	}

	private static ClientRegistration clientRegistration() {
		return ClientRegistration.withRegistrationId(REGISTRATION_ID)
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.clientId("test-client-id")
			.tokenUri("https://auth.example.com/token")
			.build();
	}

	private static OAuth2AuthorizedClient authorizedClient(ClientRegistration registration) {
		var accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, TOKEN_VALUE, Instant.now(),
				Instant.now().plusSeconds(300), Set.of());
		return new OAuth2AuthorizedClient(registration, "user", accessToken);
	}

}

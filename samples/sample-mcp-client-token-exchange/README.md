# Sample: MCP client authentication with token exchange (RFC 8693)

This sample shows how an MCP host that is an **OAuth2 resource server** can call MCP
servers with the **user's identity**, using the
[RFC 8693 token exchange](https://www.rfc-editor.org/rfc/rfc8693) grant.

## The topology

In many enterprise systems, the MCP host is not the application the user logs into:

```
user ──(authorization_code + PKCE)──> gateway ──(user JWT)──> MCP host ──(?)──> MCP servers
```

The host only holds a validated user JWT whose audience is the gateway, not the MCP
server. That token cannot be passed through to the MCP server: the
[MCP authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
requires audience validation and forbids token passthrough. Using `client_credentials`
instead loses the user's identity, which breaks per-user authorization and auditing on
the MCP server.

Token exchange solves this: the host sends the incoming user token as the
`subject_token` and receives a new token whose audience is the MCP server, with the
user's identity (`sub`) preserved.

Note: this is the single-trust-domain case, where the host and the MCP servers share one
authorization server. For the cross-domain case — the MCP server has its own
authorization server, brokered by an enterprise IdP — see the
[enterprise-managed-authorization MCP extension](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization).

## Usage

Register an OAuth2 client with the token exchange grant:

```properties
spring.security.oauth2.client.registration.token-exchange.client-id=<client-id>
spring.security.oauth2.client.registration.token-exchange.client-secret=<client-secret>
spring.security.oauth2.client.registration.token-exchange.authorization-grant-type=urn:ietf:params:oauth:grant-type:token-exchange
spring.security.oauth2.client.registration.token-exchange.provider=<your-provider>
```

Wire the customizer into the MCP client transports:

```java
@Configuration
class McpClientSecurityConfiguration {

    @Bean
    McpSyncClientCustomizer syncClientCustomizer() {
        return (name, syncSpec) -> syncSpec
            .transportContextProvider(new AuthenticationMcpTransportContextProvider());
    }

    @Bean
    McpSyncHttpClientRequestCustomizer requestCustomizer(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientService authorizedClientService) {
        var manager = OAuth2TokenExchangeSyncHttpRequestCustomizer
            .tokenExchangeAuthorizedClientManager(clientRegistrationRepository, authorizedClientService);
        return new OAuth2TokenExchangeSyncHttpRequestCustomizer(manager, "token-exchange");
    }

}
```

The incoming user `Authentication` (for example a `JwtAuthenticationToken` populated by
the resource-server support) is picked up from the `McpTransportContext` and used as the
`subject_token` of the exchange.

Set `spring.ai.mcp.client.initialized=false`, as the other samples do, so that
`initialize` and `tools/list` run inside the first user request and are covered by the
exchanged token as well. When no user authentication is present (for example on
background reconnects), the customizer skips the `Authorization` header by default; call
`failOnMissingAuthentication(true)` to fail instead, for multi-tenant setups where a
user-scoped request must never go out without the user's identity. For deployments with
genuine startup traffic, pair this customizer with a `client_credentials` registration
for protocol requests, and use token exchange for `tools/call` only.

## Subject token type

`tokenExchangeAuthorizedClientManager(...)` configures a subject token resolver that
always sends the subject token as `urn:ietf:params:oauth:token-type:access_token`.
Spring Security's default resolver sends `Jwt` principals as `...:jwt`, which works
against Spring Authorization Server but is rejected by Keycloak's standard token
exchange ("Access token type only", see the
[Keycloak token exchange guide](https://www.keycloak.org/securing-apps/token-exchange)).
The `...:access_token` type is accepted by both, keeping the setup portable.

## Keycloak notes

To run this against Keycloak instead of Spring Authorization Server:

- Standard (spec-compliant) token exchange requires **Keycloak 26.2 or later**, and must
  be enabled on the exchanging client with the `standard.token.exchange.enabled: true`
  client attribute.
- Keycloak refuses the exchange unless the exchanging client is an **audience of the
  subject token**. If user tokens are issued to a gateway or frontend client, add an
  audience mapper on those clients that includes the exchanging client's id.

## End-to-end test

The full flow — a user token obtained through the `authorization_code` flow by one
client, exchanged by a different client, then used to call a tool on a secured MCP
server that responds with the user's identity — is exercised by
`StreamableHttpTokenExchangeTests` in [integration-tests](../integration-tests).

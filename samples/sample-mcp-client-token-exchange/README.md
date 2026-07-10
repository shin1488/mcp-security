# Sample: MCP client authentication with token exchange (RFC 8693)

This sample shows how an MCP host that is an **OAuth2 resource server** — it receives
and validates the user's bearer token, but never performs the login itself — can call
MCP servers with the **user's identity**, using the
[RFC 8693 token exchange](https://www.rfc-editor.org/rfc/rfc8693) grant.

## The topology

In many enterprise systems, the MCP host is not the application the user logs into:

```
user
  │  authorization_code + PKCE
  ▼
gateway
  │  user JWT (sub: the user, aud: NOT the MCP server)
  ▼
MCP host
  │  RFC 8693 token exchange
  ▼
exchanged JWT (sub preserved, newly issued for the MCP call)
  │
  ▼
MCP server
```

The host only holds a validated user JWT whose audience is the gateway, not the MCP
server. That token cannot be passed through to the MCP server: the
[MCP authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
requires audience validation and forbids token passthrough. With `client_credentials`,
every call reaches the MCP server as the host itself: per-user authorization, audit
attribution and user-specific policies all stop working.

| How the host authenticates the MCP call | Identity seen by the MCP server |
|------------------------------------------|---------------------------------|
| Forwarding the incoming user JWT          | Rejected — wrong audience       |
| `client_credentials`                      | The host itself                 |
| Token exchange                            | The user                        |

Token exchange solves this: the host sends the incoming user token as the
`subject_token` and receives a newly issued token for the MCP call, with the user's
identity (`sub`) preserved.

Note: this is the single-trust-domain case, where the host and the MCP servers trust
the same authorization server. For the cross-domain case — the MCP server has its own
authorization server, brokered by an enterprise IdP — see the
[enterprise-managed-authorization MCP extension](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization).

## The exchange on the wire

Behind `TokenExchangeOAuth2AuthorizedClientProvider`, the host sends a regular token
request to the authorization server:

```
POST /oauth2/token
Authorization: Basic <token-exchange client credentials>

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<the incoming user access token>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
```

The response contains a new access token. As observed in the integration test:

```
incoming user token            exchanged token
  sub: test-user         ──▶     sub: test-user             (identity preserved)
  aud: default-client            aud: token-exchange-client (newly issued)
```

Token exchange preserves the user's identity but mints a fresh token: the exchanged
token is a new authorization decision made by the authorization server, not a forwarded
credential.

With Spring Authorization Server, `aud` reflects the client the token was issued to,
and the MCP server in this sample accepts the token based on the shared issuer
(`validateAudienceClaim` defaults to `false`, since not every authorization server can
issue audience-bound tokens). To bind exchanged tokens to the MCP server's own
identifier, use [resource indicators (RFC 8707)](https://www.rfc-editor.org/rfc/rfc8707),
or audience mappers on Keycloak — and once tokens are audience-bound, enable
`validateAudienceClaim(true)` on the MCP server in production.

## Usage

Register an OAuth2 client with the token exchange grant:

```properties
spring.security.oauth2.client.registration.token-exchange.client-id=<client-id>
spring.security.oauth2.client.registration.token-exchange.client-secret=<client-secret>
spring.security.oauth2.client.registration.token-exchange.authorization-grant-type=urn:ietf:params:oauth:grant-type:token-exchange
spring.security.oauth2.client.registration.token-exchange.provider=<your-provider>
```

Then wire the customizer into the MCP client transports, so that every outgoing MCP
request exchanges the current user's token before it is sent:

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
exchanged token as well.

When no user authentication is present (for example on background reconnects), the
customizer skips the `Authorization` header by default. For strict multi-tenant setups
where a user-scoped request must never go out without the user's identity, call
`failOnMissingAuthentication(true)` to fail instead.

For long-running, multi-user hosts — where protocol requests and reconnects also happen
outside any user's request — pair this customizer with a `client_credentials`
registration for protocol requests, and use token exchange for `tools/call` only. The
lazy-initialization setup above is the simplest arrangement, and is what the
integration test exercises.

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

`StreamableHttpTokenExchangeTests` in [integration-tests](../integration-tests)
verifies the complete flow: a user token obtained through the `authorization_code` flow
by one client is exchanged by a different client, and the exchanged token is used to
call a tool on a secured MCP server, which responds with the original user's identity.

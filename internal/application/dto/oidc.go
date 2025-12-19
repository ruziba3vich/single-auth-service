package dto

// OpenIDConfiguration represents the OIDC discovery document.
// Endpoint: /.well-known/openid-configuration
type OpenIDConfiguration struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserInfoEndpoint                 string   `json:"userinfo_endpoint,omitempty"`
	JWKSUri                          string   `json:"jwks_uri"`
	RegistrationEndpoint             string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	ResponseModesSupported           []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                  []string `json:"claims_supported,omitempty"`
	RevocationEndpoint               string   `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint            string   `json:"introspection_endpoint,omitempty"`
	EndSessionEndpoint               string   `json:"end_session_endpoint,omitempty"`
}

// NewOpenIDConfiguration creates the OIDC discovery document for this service.
func NewOpenIDConfiguration(issuer string) *OpenIDConfiguration {
	return &OpenIDConfiguration{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/authorize",
		TokenEndpoint:         issuer + "/token",
		JWKSUri:               issuer + "/jwks.json",
		RevocationEndpoint:    issuer + "/token/revoke",
		EndSessionEndpoint:    issuer + "/auth/logout",
		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
		},
		ResponseTypesSupported: []string{
			"code",
		},
		ResponseModesSupported: []string{
			"query",
		},
		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
			"client_credentials",
		},
		SubjectTypesSupported: []string{
			"public",
		},
		IDTokenSigningAlgValuesSupported: []string{
			"RS256",
		},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_post",
			"client_secret_basic",
			"none", // For public clients with PKCE
		},
		CodeChallengeMethodsSupported: []string{
			"S256",
		},
		ClaimsSupported: []string{
			"sub",
			"iss",
			"aud",
			"exp",
			"iat",
			"auth_time",
			"nonce",
			"email",
			"email_verified",
		},
	}
}

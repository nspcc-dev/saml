// SPDX-License-Identifier: BSD-2-Clause
// Provenance-includes-location: https://github.com/nspcc-dev/saml/blob/a32b643a25a46182499b1278293e265150056d89/samlsp/new.go
// Provenance-includes-license: BSD-2-Clause
// Provenance-includes-copyright: 2015-2023 Ross Kinder

// Package samlsp provides helpers that can be used to protect web services using SAML.
package samlsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nspcc-dev/saml"
)

type (
	// Options represents the parameters for creating a new middleware.
	Options struct {
		EntityID                   string
		URL                        url.URL
		Key                        crypto.Signer
		Certificate                *x509.Certificate
		Intermediates              []*x509.Certificate
		HTTPClient                 *http.Client
		AllowIDPInitiated          bool
		DefaultRedirectURI         string
		IDPMetadata                *saml.EntityDescriptor
		SignRequest                bool
		UseArtifactResponse        bool
		ForceAuthn                 bool // TODO(ross): this should be *bool
		RequestedAuthnContext      *saml.RequestedAuthnContext
		LogoutBindings             []string
		AuthnNameIDFormat          saml.NameIDFormat
		MetadataPath               string
		AcsPath                    string
		SloPath                    string
		AttributeConsumingServices []saml.AttributeConsumingService
		SessionProviderOptions     SessionProviderOptions
		SessionCodecOptions        SessionCodecOptions
		RequestTrackerOptions      RequestTrackerOptions
		TrackedRequestCodecOptions TrackedRequestCodecOptions
	}

	// SessionProviderOptions represents the parameters for creating a new SessionProvider.
	SessionProviderOptions struct {
		CookieName     string
		URL            url.URL
		CookieSameSite http.SameSite
	}

	// SessionCodecOptions represents the parameters for creating a new SessionProvider.
	SessionCodecOptions struct {
		URL url.URL
		Key crypto.Signer
	}

	// RequestTrackerOptions represents the parameters for creating a new RequestTracker.
	RequestTrackerOptions struct {
		RelayStateFunc func(w http.ResponseWriter, r *http.Request) string
		CookieSameSite http.SameSite
	}

	// TrackedRequestCodecOptions represents the parameters for creating a new TrackedRequestCodec.
	TrackedRequestCodecOptions struct {
		URL url.URL
		Key crypto.Signer
	}
)

func getDefaultSigningMethod(signer crypto.Signer) jwt.SigningMethod {
	if signer != nil {
		switch signer.Public().(type) {
		case *ecdsa.PublicKey:
			return jwt.SigningMethodES256
		case *rsa.PublicKey:
			return jwt.SigningMethodRS256
		}
	}
	return jwt.SigningMethodRS256
}

// DefaultSessionCodec returns the default SessionCodec for the provided options,
// a JWTSessionCodec configured to issue signed tokens.
func DefaultSessionCodec(opts SessionCodecOptions) JWTSessionCodec {
	return JWTSessionCodec{
		SigningMethod: getDefaultSigningMethod(opts.Key),
		Audience:      opts.URL.String(),
		Issuer:        opts.URL.String(),
		MaxAge:        defaultSessionMaxAge,
		Key:           opts.Key,
	}
}

// DefaultSessionProvider returns the default SessionProvider for the provided options,
// a CookieSessionProvider configured to store sessions in a cookie.
func DefaultSessionProvider(opts SessionProviderOptions, codec JWTSessionCodec) CookieSessionProvider {
	cookieName := opts.CookieName
	if cookieName == "" {
		cookieName = defaultSessionCookieName
	}
	return CookieSessionProvider{
		Name:     cookieName,
		Domain:   opts.URL.Host,
		MaxAge:   defaultSessionMaxAge,
		HTTPOnly: true,
		Secure:   opts.URL.Scheme == "https",
		SameSite: opts.CookieSameSite,
		Codec:    codec,
	}
}

// DefaultTrackedRequestCodec returns a new TrackedRequestCodec for the provided
// options, a JWTTrackedRequestCodec that uses a JWT to encode TrackedRequests.
func DefaultTrackedRequestCodec(opts TrackedRequestCodecOptions) JWTTrackedRequestCodec {
	return JWTTrackedRequestCodec{
		SigningMethod: getDefaultSigningMethod(opts.Key),
		Audience:      opts.URL.String(),
		Issuer:        opts.URL.String(),
		MaxAge:        saml.MaxIssueDelay,
		Key:           opts.Key,
	}
}

// DefaultRequestTracker returns a new RequestTracker for the provided options,
// a CookieRequestTracker which uses cookies to track pending requests.
func DefaultRequestTracker(opts RequestTrackerOptions, codec JWTTrackedRequestCodec, serviceProvider *saml.ServiceProvider) CookieRequestTracker {
	return CookieRequestTracker{
		ServiceProvider: serviceProvider,
		NamePrefix:      "saml_",
		Codec:           codec,
		MaxAge:          saml.MaxIssueDelay,
		RelayStateFunc:  opts.RelayStateFunc,
		SameSite:        opts.CookieSameSite,
	}
}

// DefaultServiceProvider returns the default saml.ServiceProvider for the provided
// options.
func DefaultServiceProvider(opts Options) saml.ServiceProvider {
	if opts.DefaultRedirectURI == "" {
		opts.DefaultRedirectURI = "/"
	}

	if len(opts.LogoutBindings) == 0 {
		opts.LogoutBindings = []string{saml.HTTPPostBinding}
	}

	if opts.MetadataPath == "" {
		opts.MetadataPath = "saml/metadata"
	}
	if opts.AcsPath == "" {
		opts.AcsPath = "saml/acs"
	}
	if opts.SloPath == "" {
		opts.SloPath = "saml/slo"
	}

	return saml.NewServiceProvider(
		saml.SPWithEntityID(opts.EntityID),
		saml.SPWithBaseURL(opts.URL),
		saml.SPWithMetadataURL(*opts.URL.ResolveReference(&url.URL{Path: opts.MetadataPath})),
		saml.SPWithAcsURL(*opts.URL.ResolveReference(&url.URL{Path: opts.AcsPath})),
		saml.SPWithSloURL(*opts.URL.ResolveReference(&url.URL{Path: opts.SloPath})),
		saml.SPWithForceAuthn(opts.ForceAuthn),
		saml.SPWithKey(opts.Key),
		saml.SPWithDefaultRedirectURI(opts.DefaultRedirectURI),
		saml.SPWithLogoutBindings(opts.LogoutBindings),
		saml.SPWithHTTPClient(opts.HTTPClient),
		saml.SPWithSignRequest(opts.SignRequest),
		saml.SPWithAllowIDPInitiated(opts.AllowIDPInitiated),
		saml.SPWithDefaultRedirectURI(opts.DefaultRedirectURI),
		saml.SPWithRequestedAuthnContext(opts.RequestedAuthnContext),
		saml.SPWithIDPMetadata(opts.IDPMetadata),
		saml.SPWithCertificate(opts.Certificate),
		saml.SPWithIntermediates(opts.Intermediates),
		saml.SPWithAuthnNameIDFormat(opts.AuthnNameIDFormat),
		saml.SPWithAttributeConsumingServices(opts.AttributeConsumingServices),
	)
}

// DefaultAssertionHandler returns the default AssertionHandler for the provided options,
// a NopAssertionHandler configured to do nothing.
func DefaultAssertionHandler(_ Options) NopAssertionHandler {
	return NopAssertionHandler{}
}

// New creates a new Middleware with the default providers for the
// given options.
//
// You can customize the behavior of the middleware in more detail by
// replacing and/or changing Session, RequestTracker, and ServiceProvider
// in the returned Middleware.
func New(opts Options) (*Middleware, error) {
	m := &Middleware{
		ServiceProvider:  DefaultServiceProvider(opts),
		Binding:          "",
		ResponseBinding:  saml.HTTPPostBinding,
		OnError:          DefaultOnError,
		Session:          DefaultSessionProvider(opts.SessionProviderOptions, DefaultSessionCodec(opts.SessionCodecOptions)),
		AssertionHandler: DefaultAssertionHandler(opts),
	}
	m.RequestTracker = DefaultRequestTracker(opts.RequestTrackerOptions, DefaultTrackedRequestCodec(opts.TrackedRequestCodecOptions), &m.ServiceProvider)
	if opts.UseArtifactResponse {
		m.ResponseBinding = saml.HTTPArtifactBinding
	}

	return m, nil
}

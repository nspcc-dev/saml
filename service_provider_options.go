package saml

import (
	"crypto"
	"crypto/x509"
	"net/http"
	"net/url"
)

type (
	// SPOption is an option parameter for ServiceProvider constructor.
	SPOption interface {
		Apply(*SPOptions)
	}

	// SPOptions represents possible options for ServiceProvider constructor.
	SPOptions struct {
		EntityID              string
		BaseURL               url.URL
		MetadataURL           url.URL
		AcsURL                url.URL
		SloURL                url.URL
		ForceAuthn            *bool
		DefaultRedirectURI    string
		LogoutBindings        []string
		Key                   crypto.Signer
		HTTPClient            *http.Client
		SignRequest           bool
		AllowIDPInitiated     bool
		RequestedAuthnContext *RequestedAuthnContext
		IDPMetadata           *EntityDescriptor
		Certificate           *x509.Certificate
		Intermediates         []*x509.Certificate
		AuthnNameIDFormat     string
	}

	spOptionFn func(*SPOptions)
)

func (fn spOptionFn) Apply(opts *SPOptions) {
	fn(opts)
}

// SPWithEntityID allows to set EntityID.
func SPWithEntityID(entityID string) SPOption {
	return spOptionFn(func(opts *SPOptions) {
		opts.EntityID = entityID
	})
}

// SPWithDefaultRedirectURI allows to set default redirect URL.
func SPWithDefaultRedirectURI(uri string) SPOption {
	return spOptionFn(func(opts *SPOptions) {
		opts.DefaultRedirectURI = uri
	})
}

// SPWithBaseURL allows to set base URL.
func SPWithBaseURL(u url.URL) SPOption {
	return spOptionFn(func(opts *SPOptions) {
		opts.BaseURL = u
	})
}

// SPWithMetadataURL allows to set SP metadata URL.
func SPWithMetadataURL(u url.URL) SPOption {
	return spOptionFn(func(opts *SPOptions) {
		opts.MetadataURL = u
	})
}

// SPWithAcsURL allows to set SP Assertion Consumer Service URL.
func SPWithAcsURL(u url.URL) SPOption {
	return spOptionFn(func(opts *SPOptions) {
		opts.AcsURL = u
	})
}

// SPWithSloURL allows to set SP logout URL.
func SPWithSloURL(u url.URL) SPOption {
	return spOptionFn(func(opts *SPOptions) {
		opts.SloURL = u
	})
}

// SPWithForceAuthn allows to set ForceAuthn option.
func SPWithForceAuthn(b bool) SPOption {
	return spOptionFn(func(opts *SPOptions) {
		// store if true only, omit otherwise.
		if b {
			opts.ForceAuthn = &b
		}
	})
}

// SPWithLogoutBindings allows to set LogoutBindings.
func SPWithLogoutBindings(b []string) SPOption {
	return spOptionFn(func(opts *SPOptions) {
		opts.LogoutBindings = b
	})
}

// SPWithKey allows to set key for signing requests. The key is not required if SignRequest=false.
func SPWithKey(key crypto.Signer) SPOption {
	return spOptionFn(func(opts *SPOptions) {
		opts.Key = key
	})
}

// SPWithHTTPClient allows to set http client.
func SPWithHTTPClient(c *http.Client) SPOption {
	return spOptionFn(func(opts *SPOptions) {
		opts.HTTPClient = c
	})
}

// SPWithSignRequest allows enabling or disabling the service provider requests signature.
func SPWithSignRequest(v bool) SPOption {
	return spOptionFn(func(opts *SPOptions) {
		opts.SignRequest = v
	})
}

// SPWithAllowIDPInitiated allows to Identity Provider–initiated login is allowed.
func SPWithAllowIDPInitiated(v bool) SPOption {
	return spOptionFn(func(opts *SPOptions) {
		opts.AllowIDPInitiated = v
	})
}

// SPWithRequestedAuthnContext allows to set what level or method of authentication SP requires.
func SPWithRequestedAuthnContext(v *RequestedAuthnContext) SPOption {
	return spOptionFn(func(opts *SPOptions) {
		opts.RequestedAuthnContext = v
	})
}

// SPWithIDPMetadata allows to set IDP metadata.
func SPWithIDPMetadata(v *EntityDescriptor) SPOption {
	return spOptionFn(func(opts *SPOptions) {
		opts.IDPMetadata = v
	})
}

// SPWithCertificate allows to set SP certificate.
func SPWithCertificate(v *x509.Certificate) SPOption {
	return spOptionFn(func(opts *SPOptions) {
		opts.Certificate = v
	})
}

// SPWithIntermediates allows to set intermediates certificates.
func SPWithIntermediates(v []*x509.Certificate) SPOption {
	return spOptionFn(func(opts *SPOptions) {
		opts.Intermediates = v
	})
}

// SPWithAuthnNameIDFormat allows to set required nameID format.
func SPWithAuthnNameIDFormat(v string) SPOption {
	return spOptionFn(func(opts *SPOptions) {
		opts.AuthnNameIDFormat = v
	})
}

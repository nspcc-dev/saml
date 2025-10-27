package samlsp

import "github.com/nspcc-dev/saml"

// AssertionHandler is an interface implemented by types that can handle
// assertions and add extra functionality
type AssertionHandler interface {
	HandleAssertion(assertion *saml.Assertion) error
}

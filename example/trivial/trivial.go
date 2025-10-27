// SPDX-License-Identifier: BSD-2-Clause
// Provenance-includes-location: https://github.com/crewjam/saml/blob/a32b643a25a46182499b1278293e265150056d89/example/trivial/trivial.go
// Provenance-includes-license: BSD-2-Clause
// Provenance-includes-copyright: 2015-2023 Ross Kinder

// Package main contains an example service provider implementation.
package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml/samlsp"
)

var samlMiddleware *samlsp.Middleware

func hello(w http.ResponseWriter, r *http.Request) {
	_, _ = fmt.Fprintf(w, "Hello, %s!", samlsp.AttributeFromContext(r.Context(), "displayName"))
}

func logout(w http.ResponseWriter, r *http.Request) {
	nameID := samlsp.AttributeFromContext(r.Context(), "urn:oasis:names:tc:SAML:attribute:subject-id")
	url, err := samlMiddleware.ServiceProvider.MakeRedirectLogoutRequest(nameID, "", "")
	if err != nil {
		panic(err) // TODO handle error
	}

	err = samlMiddleware.Session.DeleteSession(w, r)
	if err != nil {
		panic(err) // TODO handle error
	}

	w.Header().Add("Location", url.String())
	w.WriteHeader(http.StatusFound)
}

func main() {
	keyPair, err := tls.LoadX509KeyPair("myservice.cert", "myservice.key")
	if err != nil {
		panic(err) // TODO handle error
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err) // TODO handle error
	}

	idpMetadataURL, err := url.Parse("https://samltest.id/saml/idp")
	if err != nil {
		panic(err) // TODO handle error
	}
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*idpMetadataURL)
	if err != nil {
		panic(err) // TODO handle error
	}

	rootURL, err := url.Parse("http://localhost:8000")
	if err != nil {
		panic(err) // TODO handle error
	}

	samlMiddleware, _ = samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
		SignRequest: true, // some IdP require the SLO request to be signed
	})
	app := http.HandlerFunc(hello)
	slo := http.HandlerFunc(logout)

	http.Handle("/hello", samlMiddleware.RequireAccount(app))
	http.Handle("/saml/", samlMiddleware)
	http.Handle("/logout", slo)

	server := &http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

package main

import (
	"crypto/tls"
	"crypto/x509"
	"embed"
	"fmt"
)

var (
	//go:embed tokens/*
	embeddedFile embed.FS
)

func getTLSConfigFromEmbeded() (*tls.Config, error) {
	caPEM, err := embeddedFile.ReadFile("tokens/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded ca.crt: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("invalid CA format")
	}
	crtPEM, err := embeddedFile.ReadFile("tokens/cert.crt")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded cert.crt: %v", err)
	}
	keyPEM, err := embeddedFile.ReadFile("tokens/cert.key")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded cert.key: %v", err)
	}
	cert, err := tls.X509KeyPair(crtPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}
	return &tls.Config{
		RootCAs:      caPool,
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"clover3"},
		MinVersion:   tls.VersionTLS13,
		ServerName:   "tunnel",
	}, nil
}

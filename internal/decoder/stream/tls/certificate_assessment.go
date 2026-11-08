package tls

import (
	"bytes"
	"crypto/x509"
	"errors"
	"time"
)

type certificateAssessment struct {
	time                             int64
	basis, validity, selfSignature   string
	expired, notYetValid, selfSigned bool
	days                             int64
}

func assessCertificate(cert *x509.Certificate, observed int64) certificateAssessment {
	a := certificateAssessment{basis: "unavailable", validity: "unavailable", selfSignature: "not-self-issued"}
	if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
		a.selfSignature = "invalid"
		if err == nil {
			a.selfSignature = "verified"
			a.selfSigned = true
		} else {
			var insecure x509.InsecureAlgorithmError
			if errors.Is(err, x509.ErrUnsupportedAlgorithm) || errors.As(err, &insecure) {
				a.selfSignature = "unsupported"
			}
		}
	}
	if observed <= 0 {
		return a
	}
	a.time = observed
	a.basis = "capture-time"
	now := time.Unix(0, observed)
	a.validity = "valid"
	if now.Before(cert.NotBefore) {
		a.notYetValid = true
		a.validity = "not-yet-valid"
	}
	if now.After(cert.NotAfter) {
		a.expired = true
		a.validity = "expired"
	}
	seconds := cert.NotAfter.Unix() - now.Unix()
	nanos := cert.NotAfter.Nanosecond() - now.Nanosecond()
	if seconds > 0 && nanos < 0 {
		seconds--
	} else if seconds < 0 && nanos > 0 {
		seconds++
	}
	a.days = seconds / 86400
	return a
}

func certificateUnixNano(t time.Time) int64 {
	value := t.UnixNano()
	if !time.Unix(0, value).Equal(t) {
		return 0
	}
	return value
}

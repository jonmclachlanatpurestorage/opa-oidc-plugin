package internal

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/types"
	"github.com/open-policy-agent/opa/util"
	"github.com/sirupsen/logrus"
)

// Verifies an openId connect token and decodes the claims if it is valid.
var OpenIdConnectVerify = &ast.Builtin{
	Name: "io.openid.verify",
	Decl: types.NewFunction(
		types.Args(
			types.S,
			types.NewArray(nil, types.S),
		),
		types.NewArray([]types.Type{
			types.B,
			types.NewObject(nil, types.NewDynamicProperty(types.A, types.A)),
		}, nil),
	),
}

func getString(a ast.Value) (*string, error) {
	// Parse the JSON Web Token
	astEncode, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}
	encoding := string(astEncode)
	return &encoding, nil
}

// Implements full JWT decoding, validation and verification.
func builtinOpenIdConnectTokenVerifyAndParse(a ast.Value, b ast.Value) (v ast.Value, err error) {

	logrus.Debug("Processing OpenID Connect Token")

	// io.openid.verify(string, [trusted_idp's])
	//
	// If valid is true iff token is valid.
	//
	// Decoding errors etc are returned as errors.
	ret0 := ast.BooleanTerm(false)       // By default, not verified
	ret1 := ast.NewTerm(ast.NewObject()) // The parsed payload
	// Grab the token as a string.
	var token *string
	if token, err = getString(a); err != nil {
		logrus.WithField("err", err).Error("Ill-formed token string")
		return ast.NewArray(ret0, ret1), err
	}

	if token == nil {
		logrus.Debug("Failed to get token")
		return ast.NewArray(ret0, ret1), errors.New("Failed to get token from string")
	}

	// Parse the trusted issuers.
	var trustedIssuers []*string

	if arrayB, ok := b.(*ast.Array); ok {
		err = arrayB.Iter(func(trustedIssuerArrayB *ast.Term) error {
			if trustedIssuerAst, ok := trustedIssuerArrayB.Value.(ast.String); ok {
				trustedIssuerStr := string(trustedIssuerAst)
				trustedIssuers = append(trustedIssuers, &trustedIssuerStr)
			} else {
				// Ill-formed trusted issuer
				logrus.WithField("err", err).Error("Ill-formed trusted issuer")
				return fmt.Errorf("ill-formed trusted issuer")
			}
			return nil
		})

		if err != nil {
			return ast.NewArray(ret0, ret1), nil
		}
	}

	// Load or create oidc verifiers for these trusted issuers
	IdProviderVerifiers, err := GetTrustedIdentityProviderManager(trustedIssuers)
	if err != nil {
		logrus.WithField("err", err).Error("Failed to GetTrustedIdentityProviderManager")
		return ast.NewArray(ret0, ret1), err
	}

	// Verify the issuer is one of the trusted issuers, else fail.
	logrus.Debug("Verifying the token: [redacted]")
	_, err = IdProviderVerifiers.VerifyToken(token)
	if err != nil {
		ret0 = ast.BooleanTerm(false)
		logrus.WithField("err", err).Info(" Token Verify Failed")
	} else {
		ret0 = ast.BooleanTerm(true)
	}

	// Extract an ast payload from the original token payload.
	logrus.Debug("Extracting Payloads")
	val, err := extractUnverifiedPayloadAsAST(a)
	if err != nil {
		logrus.WithField("err", err).Error("extract unverified payload as ast failed")
		return ast.NewArray(ret0, ret1), err
	}

	// Package up return values as ast.
	ret1 = ast.NewTerm(val)
	return ast.NewArray(ret0, ret1), nil
}

func decodeJWTPayload(a ast.Value) (string, error) {
	// Parse the JSON Web Token
	astEncode, err := builtins.StringOperand(a, 1)
	if err != nil {
		return "", err
	}

	encoding := string(astEncode)
	if !strings.Contains(encoding, ".") {
		return "", errors.New("encoded JWT had no period separators")
	}

	parts := strings.Split(encoding, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("encoded JWT must have 3 sections, found %d", len(parts))
	}

	return parts[1], nil
}

func builtinBase64UrlDecode(a ast.Value) (ast.Value, error) {
	str, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}
	s := string(str)

	// Some base64url encoders omit the padding at the end, so this case
	// corrects such representations using the method given in RFC 7515
	// Appendix C: https://tools.ietf.org/html/rfc7515#appendix-C
	if !strings.HasSuffix(s, "=") {
		switch len(s) % 4 {
		case 0:
		case 2:
			s += "=="
		case 3:
			s += "="
		default:
			return nil, fmt.Errorf("illegal base64url string: %s", s)
		}
	}
	result, err := base64.URLEncoding.DecodeString(s)
	return ast.String(result), err
}

func builtinJSONUnmarshal(a ast.Value) (ast.Value, error) {

	str, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	var x interface{}

	if err := util.UnmarshalJSON([]byte(str), &x); err != nil {
		return nil, err
	}

	return ast.InterfaceToValue(x)
}

func extractJSONObject(s string) (ast.Object, error) {
	// XXX: This code relies on undocumented behavior of Go's
	// json.Unmarshal using the last occurrence of duplicate keys in a JSON
	// Object. If duplicate keys are present in a JWT, the last must be
	// used or the token rejected. Since detecting duplicates is tantamount
	// to parsing it ourselves, we're relying on the Go implementation
	// using the last occurring instance of the key, which is the behavior
	// as of Go 1.8.1.
	v, err := builtinJSONUnmarshal(ast.String(s))
	if err != nil {
		return nil, fmt.Errorf("invalid JSON: %v", err)
	}

	o, ok := v.(ast.Object)
	if !ok {
		return nil, errors.New("decoded JSON type was not an Object")
	}

	return o, nil
}

func extractUnverifiedPayloadAsAST(token ast.Value) (ast.Value, error) {
	jwtTokenPayload, err := decodeJWTPayload(token)
	if err != nil {
		return nil, err
	}

	p, err := builtinBase64UrlDecode(ast.String(jwtTokenPayload))
	if err != nil {
		return nil, fmt.Errorf("JWT payload had invalid encoding: %v", err)
	}

	payload, err := extractJSONObject(string(p.(ast.String)))
	if err != nil {
		return nil, err
	}

	return payload, nil
}

func init() {
	ast.RegisterBuiltin(OpenIdConnectVerify)
	topdown.RegisterFunctionalBuiltin2(OpenIdConnectVerify.Name, builtinOpenIdConnectTokenVerifyAndParse)
}

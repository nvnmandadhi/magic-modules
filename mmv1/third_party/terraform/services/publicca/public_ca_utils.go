package publicca

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/go-jose/go-jose/v3"
	"io"
	"log"
	"net/http"
	"regexp"
	"runtime"
	"strconv"
)

const (
	GCPDirectoryProduction = "https://dv.acme-v02.api.pki.goog"
	GCPDirectoryStaging    = "https://dv.acme-v02.test-api.pki.goog"
)

type Account struct {
	Email                  string          `json:"email"`
	TermsOfServiceAgreed   bool            `json:"termsOfServiceAgreed"`
	ExternalAccountBinding json.RawMessage `json:"externalAccountBinding"`
	OnlyReturnExisting     bool            `json:"onlyReturnExisting"`
	Status                 string          `json:"status"`
}

type AccountRollover struct {
	Account string `json:"account"`
	OldKey  string `json:"oldKey"`
}

type nonceSource struct {
	NonceURL string
}

func (n *nonceSource) Nonce() (string, error) {
	response, _ := http.Head(n.NonceURL)
	nonce := response.Header.Get("replay-nonce")
	if len(nonce) == 0 {
		return "", fmt.Errorf("couldn't find nonce header")
	}
	return nonce, nil
}

func createNewAccountUsingEab(email string, isStagingEnv bool, privateKeyPem string, keyId string, hmacEncoded string) (string, error) {
	baseUrl := getBaseUrl(isStagingEnv)
	url := baseUrl + "/new-account"
	signedEab, err := getSignedEab(url, keyId, hmacEncoded, privateKeyPem)
	if err != nil {
		log.Fatalf("couldn't create signed EAB: %s", err)
	}
	payload := Account{
		Email:                  email,
		TermsOfServiceAgreed:   true,
		ExternalAccountBinding: []byte(signedEab.FullSerialize()),
		OnlyReturnExisting:     false,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("error occurred marshaling request payload")
	}
	signer, _ := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       jose.JSONWebKey{Key: getPrivateKey(privateKeyPem), KeyID: keyId},
	},
		&jose.SignerOptions{
			EmbedJWK:    true,
			NonceSource: &nonceSource{NonceURL: url},
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url": url,
			},
		})
	signedPayload, err := signer.Sign(body)
	if err != nil {
		return "", fmt.Errorf("error occurred signing payload")
	}
	signedBody := bytes.NewBufferString(signedPayload.FullSerialize())
	request, err := http.NewRequest("POST", url, signedBody)
	if err != nil {
		return "", fmt.Errorf("error occurred marshaling request payload")
	}
	request.Header.Add("Content-Type", "application/jose+json")
	userAgent := fmt.Sprintf("%s (%s; %s)", "gcp-acme/0.1", runtime.GOOS, runtime.GOARCH)
	request.Header.Add("User-Agent", userAgent)
	request.Header.Add("Accept-Language", "en-US")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("error occurred making request")
	}
	defer func(Body io.ReadCloser) {
		err = Body.Close()
		if err != nil {
			log.Println("[DEBUG] error occurred closing request")
		}
	}(response.Body)
	if _, err = io.ReadAll(response.Body); err != nil {
		return "", fmt.Errorf("error occurred reading response")
	}
	res, _ := io.ReadAll(response.Body)
	log.Printf("Response Body: %s Code: %s", res, response.Status)
	if valid, _ := regexp.MatchString("^2", strconv.Itoa(response.StatusCode)); !valid {
		return "", errors.New("failed to create account, error response from the server")
	}
	accountUri, err := response.Location()
	if err != nil {
		return "", fmt.Errorf("error occurred reading location header from the response")
	}
	if len(accountUri.String()) == 0 {
		return "", errors.New("error occurred creating account")
	}
	log.Printf("[DEBUG] Account created, URL: %s\n", accountUri)
	return accountUri.String(), nil
}

func updateAccountEmail(accountUri string, privateKeyPem string, email string, keyId string, hmacEncoded string) error {
	signedEab, err := getSignedEab(accountUri, keyId, hmacEncoded, privateKeyPem)
	if err != nil {
		log.Fatalf("couldn't create signed EAB: %s", err)
	}
	payload := Account{
		Email:                  email,
		TermsOfServiceAgreed:   true,
		ExternalAccountBinding: []byte(signedEab.FullSerialize()),
		OnlyReturnExisting:     true,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error occurred marshaling request payload")
	}
	signer, _ := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       jose.JSONWebKey{Key: getPrivateKey(privateKeyPem), KeyID: keyId},
	},
		&jose.SignerOptions{
			EmbedJWK:    true,
			NonceSource: &nonceSource{NonceURL: accountUri},
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url": accountUri,
			},
		})
	signedPayload, err := signer.Sign(body)
	if err != nil {
		return fmt.Errorf("error occurred signing payload")
	}
	signedBody := bytes.NewBufferString(signedPayload.FullSerialize())
	request, err := http.NewRequest("POST", accountUri, signedBody)
	if err != nil {
		return fmt.Errorf("error occurred marshaling request payload")
	}
	request.Header.Add("Content-Type", "application/jose+json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("error occurred making request")
	}
	defer func(Body io.ReadCloser) {
		err = Body.Close()
		if err != nil {
			log.Println("[DEBUG] error occurred closing request")
		}
	}(response.Body)
	if _, err = io.ReadAll(response.Body); err != nil {
		return fmt.Errorf("error occurred reading response")
	}
	if response.StatusCode == http.StatusOK {
		return errors.New("failed to update account, error response from the server")
	}
	log.Printf("[DEBUG] Account updated, URL: %s\n", accountUri)
	return nil
}

func accountKeyRollover(accountUri string, isStagingEnv bool, oldPrivateKey string, newPrivateKey string) error {
	jwk := jose.JSONWebKey{Key: getPrivateKey(newPrivateKey)}
	jwkJson, err := jwk.Public().MarshalJSON()
	if err != nil {
		log.Fatalf("couldn't create signed EAB: %s", err)
	}
	payload := AccountRollover{
		Account: accountUri,
		OldKey:  string(jwkJson),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error occurred marshaling request payload")
	}
	signer, _ := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       jose.JSONWebKey{Key: getPrivateKey(newPrivateKey)},
	},
		&jose.SignerOptions{
			EmbedJWK: true,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url": getBaseUrl(isStagingEnv) + "/key-change",
			},
		})
	signedPayload, err := signer.Sign(body)

	outerSigner, _ := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       jose.JSONWebKey{Key: getPrivateKey(oldPrivateKey), KeyID: accountUri},
	},
		&jose.SignerOptions{
			EmbedJWK:    true,
			NonceSource: &nonceSource{NonceURL: accountUri},
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url": getBaseUrl(isStagingEnv) + "/key-change",
			},
		})
	update, err := outerSigner.Sign([]byte(signedPayload.FullSerialize()))
	if err != nil {
		return fmt.Errorf("error occurred signing payload")
	}
	signedBody := bytes.NewBufferString(update.FullSerialize())
	request, err := http.NewRequest("POST", getBaseUrl(isStagingEnv)+"/key-change", signedBody)
	if err != nil {
		return fmt.Errorf("error occurred marshaling request payload")
	}
	request.Header.Add("Content-Type", "application/jose+json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("error occurred making request")
	}
	defer func(Body io.ReadCloser) {
		err = Body.Close()
		if err != nil {
			log.Println("[DEBUG] error occurred closing request")
		}
	}(response.Body)
	if _, err = io.ReadAll(response.Body); err != nil {
		return fmt.Errorf("error occurred reading response")
	}
	if response.StatusCode == http.StatusOK {
		return errors.New("failed to update account, error response from the server")
	}
	log.Printf("[DEBUG] Account updated, URL: %s\n", accountUri)
	return nil
}

func deactivateAccount(accountUri string, privateKeyPem string) error {
	payload := Account{
		Status: "deactivated",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error occurred marshaling request payload")
	}
	signer, _ := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       jose.JSONWebKey{Key: getPrivateKey(privateKeyPem), KeyID: accountUri},
	},
		&jose.SignerOptions{
			EmbedJWK:    true,
			NonceSource: &nonceSource{NonceURL: accountUri},
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url": accountUri,
			},
		})
	signedPayload, err := signer.Sign(body)
	if err != nil {
		return fmt.Errorf("error occurred signing payload")
	}
	signedBody := bytes.NewBufferString(signedPayload.FullSerialize())
	request, err := http.NewRequest("POST", accountUri, signedBody)
	if err != nil {
		return fmt.Errorf("error occurred marshaling request payload")
	}
	request.Header.Add("Content-Type", "application/jose+json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("error occurred making request")
	}
	defer func(Body io.ReadCloser) {
		err = Body.Close()
		if err != nil {
			log.Println("[DEBUG] error occurred closing request")
		}
	}(response.Body)
	if _, err = io.ReadAll(response.Body); err != nil {
		return fmt.Errorf("error occurred reading response")
	}
	res, _ := io.ReadAll(response.Body)
	log.Printf("=========================> response: %v", res)
	if response.StatusCode == http.StatusOK {
		return errors.New("failed to deactivate account, error response from the server")
	}
	log.Printf("[DEBUG] Account deactivated.")
	return nil
}

func getSignedEab(url string, keyId string, hmacEncoded string, privateKeyPem string) (*jose.JSONWebSignature, error) {
	log.Printf("[DEBUG] Using server: %s\n", url)
	hmac, err := base64.StdEncoding.DecodeString(hmacEncoded)
	if err != nil {
		return nil, fmt.Errorf("error occurred decoding hmac key: %s", err)
	}
	jwk := jose.JSONWebKey{Key: getPrivateKey(privateKeyPem)}
	jwkJson, err := jwk.Public().MarshalJSON()
	if err != nil {
		log.Fatalf("Failed to serialize jwk: %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       hmac,
	},
		&jose.SignerOptions{
			EmbedJWK: false,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": keyId,
				"url": url,
			},
		},
	)
	if err != nil {
		log.Fatalf("Failed to create hmac signer: %v", err)
	}
	signedEab, err := signer.Sign(jwkJson)
	if err != nil {
		log.Fatalf("Failed to create JWS: %v", err)
	}
	return signedEab, nil
}

func getBaseUrl(isStagingEnv bool) string {
	if isStagingEnv {
		return GCPDirectoryStaging
	}
	return GCPDirectoryProduction
}

func getPrivateKey(privateKeyPem string) *rsa.PrivateKey {
	if privateKeyPem != "" {
		log.Printf("[DEBUG] using provided private key")
		block, _ := pem.Decode([]byte(privateKeyPem))
		_key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("[DEBUG] couldn't parse private key: %v", err)
		}
		return _key.(*rsa.PrivateKey)
	} else {
		log.Printf("[DEBUG] creating a new private key of type ED25519")
		_key, _ := rsa.GenerateKey(rand.Reader, 2048)
		return _key
	}
}

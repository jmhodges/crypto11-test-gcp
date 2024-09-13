package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/ThalesIgnite/crypto11"
	"github.com/miekg/pkcs11"
)

func main() {
	// things we need to test:
	// crypto11.GenerateECDSAKeyPairOnSlot
	// crypto11.PKCS11RandReader
	// crypto11.FindKeyPair
	//   - with ECDSA key
	//   - with RSA key
	// crypto11.GenerateRSAKeyPairOnSlot
	//   - I don't think we actually call this when using an HSM?
	// also look into whether we should set log_directory and other options
	// logs go to stdout if not log is specified which might be fine?
	conf := crypto11.PKCS11Config{
		Path: os.Args[1],
		// This token label must match up with the `label` set in the kmsp11 config
		// for a given key.
		// In Autograph, this means either duplicating this label in k8s + autograph
		// config, or finding some way for autograph to pull it at runtime.
		// An alternative would be to only set the infra bits in k8s (as env vars)
		// and then have autograph generate and write the kmsp11 config at runtime
		// which would combine the stuff coming from the env with the stuff (like label)
		// coming from the config
		// in GCP terms, this token is a "key ring", and we would expect the token label to be something like:
		// projects/bhearsum-test/locations/northamerica-northeast2/keyRings/bhearsum-crypto11-test
		TokenLabel: os.Args[2],
	}

	err := os.Setenv("KMS_PKCS11_CONFIG", os.Args[3])
	if err != nil {
		log.Fatal(err)
	}

	ctx, err := crypto11.Configure(&conf)
	if err != nil {
		log.Fatal(err)
	}
	if ctx != nil {
	}

	switch os.Args[4] {
	// all of the different things we need to test
	case "generate-ecdsa":
		log.Print("Testing ECDSA generation key on HSM")
		log.Print("***********************************")
		priv, pub, err := testGenerateEcdsa(ctx, []byte(os.Args[5]))
		if err != nil {
			log.Printf("failed to generate ecdsa: %v", err)
			break
		}
		log.Print("Succeeded!")
		log.Printf("privkey is: %v", priv)
		log.Printf("pubkey is: %v", pub)
	case "generate-ecdsa-bypassing-crypto11":
		log.Print("Testing ECDSA generation key on HSM")
		log.Print("***********************************")
		priv, pub, err := testGenerateEcdsaBypassingCrypto11(ctx, conf, []byte(os.Args[5]))
		if err != nil {
			log.Printf("failed to generate ecdsa: %v", err)
			break
		}
		log.Print("Succeeded!")
		log.Printf("privkey is: %v", priv)
		log.Printf("pubkey is: %v", pub)
	case "rand-reader":
		data, err := testRandReader(ctx)
		if err != nil {
			log.Printf("rand reader test failed: %v", err)
			break
		}
		log.Print("Succeeded!")
		encoded := make([]byte, hex.EncodedLen(len(data)))
		hex.Encode(encoded, data)
		log.Printf("random hex encoded data is: %s", encoded)
	case "find-keypair":
		handle, err := testFindKeyPair(ctx, []byte(os.Args[5]))
		if err != nil {
			log.Printf("failed to find key pair: %v", err)
			break
		}
		log.Print("Succeeded!")
		log.Printf("handle is: %s", handle)
	}
}

func testGenerateEcdsa(ctx *pkcs11.Ctx, keyName []byte) (*crypto11.PKCS11PrivateKeyECDSA, *ecdsa.PublicKey, error) {
	// basically just https://github.com/mozilla-services/autograph/blob/657f45ca42b7b392378485dd4c731d02037c0c75/signer/signer.go#L422-L438
	var slots []uint
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, nil, err
	}
	if len(slots) < 1 {
		return nil, nil, fmt.Errorf("no usable slots")
	}
	// welp, the google library doesn't seem to like what crypto11 does
	// we end up with:
	// I20240912 16:09:41.182875 132216886245184 logging.cc:185] returning 0xd1 from C_GenerateKeyPair due to status INVALID_ARGUMENT: at session.cc:535: this token does not accept public key attributes [type.googleapis.com/kmsp11.StatusDetails='CK_RV=0xd1']
	// https://github.com/GoogleCloudPlatform/kms-integrations/issues/1 seems to
	// be reporting the same thing
	// google recommends https://github.com/sethvargo/go-gcpkms in that issue
	priv, err := crypto11.GenerateECDSAKeyPairOnSlot(slots[0], keyName, keyName, elliptic.P384())
	if err != nil {
		return nil, nil, err
	}
	// slightly different than autograph code because `priv` is not bound as a generic
	// crypto.PrivateKey here; it's already a PKCS11PrivateKeyECDSA
	pub := priv.PubKey.(ecdsa.PublicKey)
	return priv, &pub, nil
}

func testGenerateEcdsaBypassingCrypto11(ctx *pkcs11.Ctx, conf crypto11.PKCS11Config, keyName []byte) (*crypto11.PKCS11PrivateKeyECDSA, *ecdsa.PublicKey, error) {
	// basically just https://github.com/mozilla-services/autograph/blob/657f45ca42b7b392378485dd4c731d02037c0c75/signer/signer.go#L422-L438
	var slots []uint
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, nil, err
	}
	if len(slots) < 1 {
		return nil, nil, fmt.Errorf("no usable slots")
	}

	publicKeyTemplate := []*pkcs11.Attribute{}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyName),
		// not provided by pkcs11 - pulled from https://github.com/GoogleCloudPlatform/kms-integrations/blob/4498bffda1e3bfe8750c56ff6f8c0da700152052/kmsp11/kmsp11.h#L30
		// and https://github.com/GoogleCloudPlatform/kms-integrations/blob/4498bffda1e3bfe8750c56ff6f8c0da700152052/kmsp11/kmsp11.h#L33
		pkcs11.NewAttribute(0x80000000|0x1E100|0x01, 12),
	}
	priv, err := crypto11.GenerateECDSAKeyPairOnSlotWithSpecificAttributes(slots[0], keyName, keyName, elliptic.P384(), publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		return nil, nil, err
	}
	// slightly different than autograph code because `priv` is not bound as a generic
	// crypto.PrivateKey here; it's already a PKCS11PrivateKeyECDSA
	pub := priv.PubKey.(ecdsa.PublicKey)
	return priv, &pub, nil
}

func testRandReader(ctx *pkcs11.Ctx) ([]byte, error) {
	rand := new(crypto11.PKCS11RandReader)
	data := make([]byte, 512)
	read, err := rand.Read(data)
	if err != nil {
		return nil, err
	}
	if read != 512 {
		return nil, fmt.Errorf("failed to read 512 bytes of random data")
	}
	return data, nil
}

func testFindKeyPair(ctx *pkcs11.Ctx, label []byte) (uint, error) {
	key, err := crypto11.FindKeyPair(nil, label)
	if err != nil {
		return 0, err
	}
	switch key2 := key.(type) {
	case *crypto11.PKCS11PrivateKeyECDSA:
		return uint(key2.Handle), nil
	case *crypto11.PKCS11PrivateKeyRSA:
		return uint(key2.Handle), nil
	}
	return 0, fmt.Errorf("key is not in the HSM; did you specify the label of something that exists in the keyring?")
}

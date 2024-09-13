package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/ThalesIgnite/crypto11"
	"github.com/miekg/pkcs11"
	"github.com/youtube/vitess/go/pools"
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
		priv, pub, err := testGenerateEcdsa(ctx)
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
		priv, pub, err := testGenerateEcdsaBypassingCrypto11(ctx, conf)
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

func testGenerateEcdsa(ctx *pkcs11.Ctx) (*crypto11.PKCS11PrivateKeyECDSA, *ecdsa.PublicKey, error) {
	// basically just https://github.com/mozilla-services/autograph/blob/657f45ca42b7b392378485dd4c731d02037c0c75/signer/signer.go#L422-L438
	var slots []uint
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, nil, err
	}
	if len(slots) < 1 {
		return nil, nil, fmt.Errorf("no usable slots")
	}
	keyNameBytes := []byte("test-ecdsa-key")
	// welp, the google library doesn't seem to like what crypto11 does
	// we end up with:
	// I20240912 16:09:41.182875 132216886245184 logging.cc:185] returning 0xd1 from C_GenerateKeyPair due to status INVALID_ARGUMENT: at session.cc:535: this token does not accept public key attributes [type.googleapis.com/kmsp11.StatusDetails='CK_RV=0xd1']
	// https://github.com/GoogleCloudPlatform/kms-integrations/issues/1 seems to
	// be reporting the same thing
	// google recommends https://github.com/sethvargo/go-gcpkms in that issue
	priv, err := crypto11.GenerateECDSAKeyPairOnSlot(slots[0], keyNameBytes, keyNameBytes, elliptic.P384())
	if err != nil {
		return nil, nil, err
	}
	// slightly different than autograph code because `priv` is not bound as a generic
	// crypto.PrivateKey here; it's already a PKCS11PrivateKeyECDSA
	pub := priv.PubKey.(ecdsa.PublicKey)
	return priv, &pub, nil
}

// copied from crypto11:
// https://github.com/ThalesGroup/crypto11/blob/c73933259cb60509d00f32306eea53d10f8e8f10/crypto11.go#L150
type libCtx struct {
	ctx *pkcs11.Ctx
	cfg *crypto11.PKCS11Config

	token *pkcs11.TokenInfo
	slot  uint
}

// copied from crypto11:
// https://github.com/ThalesGroup/crypto11/blob/c73933259cb60509d00f32306eea53d10f8e8f10/crypto11.go#L160C1-L174C2
func findToken(instance libCtx, slots []uint, serial string, label string) (uint, *pkcs11.TokenInfo, error) {
	for _, slot := range slots {
		tokenInfo, err := instance.ctx.GetTokenInfo(slot)
		if err != nil {
			return 0, nil, err
		}
		if tokenInfo.SerialNumber == serial {
			return slot, &tokenInfo, nil
		}
		if tokenInfo.Label == label {
			return slot, &tokenInfo, nil
		}
	}
	return 0, nil, crypto11.ErrTokenNotFound
}

type sessionPool struct {
	m sync.RWMutexpool map[uint]*pools.Resour
}

func withSession(slot uint, f func(session *crypto11.PKCS11Session) error) error {
	sessionPool := pool.Get(slot)
	if sessionPool == nil {
		return fmt.Errorf("crypto11: no session for slot %d", slot)
	}

	ctx := context.Background()
	if instance.cfg.PoolWaitTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), instance.cfg.PoolWaitTimeout)
		defer cancel()
	}

	session, err := sessionPool.Get(ctx)
	if err != nil {
		return err
	}
	defer sessionPool.Put(session)

	s := session.(*PKCS11Session)
	err = f(s)
	if err != nil {
		// if a request required login, then try to login
		if perr, ok := err.(pkcs11.Error); ok && perr == pkcs11.CKR_USER_NOT_LOGGED_IN && instance.cfg.Pin != "" {
			if err = s.Ctx.Login(s.Handle, pkcs11.CKU_USER, instance.cfg.Pin); err != nil {
				return err
			}
			// retry after login
			return f(s)
		}

		return err
	}

	return nil
}

// Ensures that sessions are setup.
func ensureSessions(ctx *libCtx, slot uint) error {
	if err := setupSessions(ctx, slot); err != nil && err != errSlotBusy {
		return err
	}
	return nil
}

// Create the session pool for a given slot if it does not exist
// already.
func setupSessions(c *libCtx, slot uint) error {
	return pool.PutIfAbsent(slot, pools.NewResourcePool(
		func() (pools.Resource, error) {
			s, err := newSession(c.ctx, slot)
			if err != nil {
				return nil, err
			}

			if instance.token.Flags&pkcs11.CKF_LOGIN_REQUIRED != 0 && instance.cfg.Pin != "" {
				// login required if a pool evict idle sessions or
				// for the first connection in the pool (handled in lib conf)
				if instance.cfg.IdleTimeout > 0 {
					if err = loginToken(s); err != nil {
						return nil, err
					}
				}
			}

			return s, nil
		},
		c.cfg.MaxSessions,
		c.cfg.MaxSessions,
		c.cfg.IdleTimeout,
	))
}
func testGenerateEcdsaBypassingCrypto11(ctx *pkcs11.Ctx, conf crypto11.PKCS11Config) (*crypto11.PKCS11PrivateKeyECDSA, *ecdsa.PublicKey, error) {
	// basically just https://github.com/mozilla-services/autograph/blob/657f45ca42b7b392378485dd4c731d02037c0c75/signer/signer.go#L422-L438
	var slots []uint
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, nil, err
	}
	if len(slots) < 1 {
		return nil, nil, fmt.Errorf("no usable slots")
	}
	keyNameBytes := []byte("test-ecdsa-key")

	// TODO: test that using our own context interops OK with the one that crypto11 internally holds
	// eg: do a series of operations both by hand and through crypto11 to make sure nothing
	// breaks
	// we need an `instance` object to which is just a Context with a couple of pieces of data
	// see https://github.com/ThalesGroup/crypto11/blob/c73933259cb60509d00f32306eea53d10f8e8f10/crypto11.go#L230
	instance := libCtx { 
		ctx: ctx,
		cfg: &conf,
	}

	instance.slot, instance.token, err = findToken(slots, conf.TokenSerial, conf.TokenLabel)
	if err != nil {
		return nil, nil, err
	}
	// in the real world, we might have addition setup to do here - see the link above

	// and below here is a tweaked version of what crypto11.GenerateECDSAKeyPairOnSession/Slot does:
	// https://github.com/ThalesGroup/crypto11/blob/c73933259cb60509d00f32306eea53d10f8e8f10/ecdsa.go#L234
	// https://github.com/ThalesGroup/crypto11/blob/c73933259cb60509d00f32306eea53d10f8e8f10/ecdsa.go#L253
	var k *crypto11.PKCS11PrivateKeyECDSA
	err = ensureSessions(instance, slots[0])
	if err != nil {
		return nil, nil, err
	}
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

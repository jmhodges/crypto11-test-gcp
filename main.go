package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
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

func loginToken(instance *libCtx, s *crypto11.PKCS11Session) error {
	// login is pkcs11 context wide, not just handle/session scoped
	err := s.Ctx.Login(s.Handle, pkcs11.CKU_USER, instance.cfg.Pin)
	if err != nil {
		if code, ok := err.(pkcs11.Error); ok && code == pkcs11.CKR_USER_ALREADY_LOGGED_IN {
			return nil
		}
		log.Printf("Failed to open PKCS#11 Session: %s", err.Error())

		closeErr := s.CloseSession()
		if closeErr != nil {
			log.Printf("Failed to close session: %s", closeErr.Error())
		}

		// Return the first error we encountered
		return err
	}
	return nil
}

func newSession(ctx *pkcs11.Ctx, slot uint) (*crypto11.PKCS11Session, error) {
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, err
	}
	return &crypto11.PKCS11Session{ctx, session}, nil
}

type sessionPool struct {
	m sync.RWMutex
	pool map[uint]*pools.ResourcePool
}

func (p *sessionPool) Get(slot uint) *pools.ResourcePool {
	p.m.RLock()
	defer p.m.RUnlock()
	return p.pool[slot]
}

func (p *sessionPool) PutIfAbsent(slot uint, pool *pools.ResourcePool) error {
	p.m.Lock()
	defer p.m.Unlock()
	if _, ok := p.pool[slot]; ok {
		return errSlotBusy
	}
	p.pool[slot] = pool
	return nil
}


var pool = newSessionPool()

func newSessionPool() *sessionPool {
	return &sessionPool{
		pool: map[uint]*pools.ResourcePool{},
	}
}

func withSession(instance libCtx, slot uint, f func(session *crypto11.PKCS11Session) error) error {
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

	s := session.(*crypto11.PKCS11Session)
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

var errSlotBusy = errors.New("pool slot busy")

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

			if c.token.Flags&pkcs11.CKF_LOGIN_REQUIRED != 0 && c.cfg.Pin != "" {
				// login required if a pool evict idle sessions or
				// for the first connection in the pool (handled in lib conf)
				if c.cfg.IdleTimeout > 0 {
					if err = loginToken(c, s); err != nil {
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

const labelLength = 64
func generateKeyLabel() ([]byte, error) {
	rawLabel := make([]byte, labelLength / 2)
	var rand crypto11.PKCS11RandReader
	sz, err := rand.Read(rawLabel)
	if err != nil {
		return nil, err
	}
	if sz < len(rawLabel) {
		return nil, crypto11.ErrCannotGetRandomData
	}
	label := make([]byte, labelLength)
	hex.Encode(label, rawLabel)
	return label, nil
}

type curveInfo struct {
	// ASN.1 marshaled OID
	oid []byte

	// Curve definition in Go form
	curve elliptic.Curve
}

func mustMarshal(val interface{}) []byte {
	if b, err := asn1.Marshal(val); err != nil {
		panic(err)
	} else {
		return b
	}
}

var wellKnownCurves = map[string]curveInfo{
	"P-192": {
		mustMarshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 1}),
		nil,
	},
	"P-224": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 33}),
		elliptic.P224(),
	},
	"P-256": {
		mustMarshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}),
		elliptic.P256(),
	},
	"P-384": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}),
		elliptic.P384(),
	},
	"P-521": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 35}),
		elliptic.P521(),
	},

	"K-163": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 1}),
		nil,
	},
	"K-233": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 26}),
		nil,
	},
	"K-283": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 16}),
		nil,
	},
	"K-409": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 36}),
		nil,
	},
	"K-571": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 38}),
		nil,
	},

	"B-163": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 15}),
		nil,
	},
	"B-233": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 27}),
		nil,
	},
	"B-283": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 17}),
		nil,
	},
	"B-409": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 37}),
		nil,
	},
	"B-571": {
		mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 39}),
		nil,
	},
}

func marshalEcParams(c elliptic.Curve) ([]byte, error) {
	if ci, ok := wellKnownCurves[c.Params().Name]; ok {
		return ci.oid, nil
	}
	// TODO use ANSI X9.62 ECParameters representation instead
	return nil, crypto11.ErrUnsupportedEllipticCurve
}

func unmarshalEcParams(b []byte) (elliptic.Curve, error) {
	// See if it's a well-known curve
	for _, ci := range wellKnownCurves {
		if bytes.Compare(b, ci.oid) == 0 {
			if ci.curve != nil {
				return ci.curve, nil
			}
			return nil, crypto11.ErrUnsupportedEllipticCurve
		}
	}
	// TODO try ANSI X9.62 ECParameters representation
	return nil, crypto11.ErrUnsupportedEllipticCurve
}

func unmarshalEcPoint(b []byte, c elliptic.Curve) (x *big.Int, y *big.Int, err error) {
	// Decoding an octet string in isolation seems to be too hard
	// with encoding.asn1, so we do it manually. Look away now.
	if b[0] != 4 {
		return nil, nil, crypto11.ErrMalformedDER
	}
	var l, r int
	if b[1] < 128 {
		l = int(b[1])
		r = 2
	} else {
		ll := int(b[1] & 127)
		if ll > 2 { // unreasonably long
			return nil, nil, crypto11.ErrMalformedDER
		}
		l = 0
		for i := int(0); i < ll; i++ {
			l = 256*l + int(b[2+i])
		}
		r = ll + 2
	}
	if r+l > len(b) {
		return nil, nil, crypto11.ErrMalformedDER
	}
	pointBytes := b[r:]
	x, y = elliptic.Unmarshal(c, pointBytes)
	if x == nil || y == nil {
		err = crypto11.ErrMalformedPoint
	}
	return
}


func exportECDSAPublicKey(session *crypto11.PKCS11Session, pubHandle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	var err error
	var attributes []*pkcs11.Attribute
	var pub ecdsa.PublicKey
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ECDSA_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}
	if attributes, err = session.Ctx.GetAttributeValue(session.Handle, pubHandle, template); err != nil {
		return nil, err
	}
	if pub.Curve, err = unmarshalEcParams(attributes[0].Value); err != nil {
		return nil, err
	}
	if pub.X, pub.Y, err = unmarshalEcPoint(attributes[1].Value, pub.Curve); err != nil {
		return nil, err
	}
	return &pub, nil
}


func GenerateECDSAKeyPairOnSession(session *crypto11.PKCS11Session, slot uint, id []byte, label []byte, c elliptic.Curve) (*crypto11.PKCS11PrivateKeyECDSA, error) {
	var err error
	var pub crypto.PublicKey

	if label == nil {
		if label, err = generateKeyLabel(); err != nil {
			return nil, err
		}
	}
	if id == nil {
		if id, err = generateKeyLabel(); err != nil {
			return nil, err
		}
	}
	publicKeyTemplate := []*pkcs11.Attribute{
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		// not provided by pkcs11 - pulled from https://github.com/GoogleCloudPlatform/kms-integrations/blob/4498bffda1e3bfe8750c56ff6f8c0da700152052/kmsp11/kmsp11.h#L30
		// and https://github.com/GoogleCloudPlatform/kms-integrations/blob/4498bffda1e3bfe8750c56ff6f8c0da700152052/kmsp11/kmsp11.h#L33
		pkcs11.NewAttribute(0x80000000 | 0x1E100 | 0x01, 12),
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA_KEY_PAIR_GEN, nil)}
	pubHandle, privHandle, err := session.Ctx.GenerateKeyPair(session.Handle,
		mech,
		publicKeyTemplate,
		privateKeyTemplate)
	if err != nil {
		return nil, err
	}
	if pub, err = exportECDSAPublicKey(session, pubHandle); err != nil {
		return nil, err
	}
	priv := crypto11.PKCS11PrivateKeyECDSA{crypto11.PKCS11PrivateKey{crypto11.PKCS11Object{privHandle, slot}, pub}}
	return &priv, nil
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

	instance.slot, instance.token, err = findToken(instance, slots, conf.TokenSerial, conf.TokenLabel)
	if err != nil {
		return nil, nil, err
	}
	// in the real world, we might have addition setup to do here - see the link above

	// and below here is a tweaked version of what crypto11.GenerateECDSAKeyPairOnSession/Slot does:
	// https://github.com/ThalesGroup/crypto11/blob/c73933259cb60509d00f32306eea53d10f8e8f10/ecdsa.go#L234
	// https://github.com/ThalesGroup/crypto11/blob/c73933259cb60509d00f32306eea53d10f8e8f10/ecdsa.go#L253
	var k *crypto11.PKCS11PrivateKeyECDSA
	err = ensureSessions(&instance, slots[0])
	if err != nil {
		return nil, nil, err
	}
	err = withSession(instance, slots[0], func(session *crypto11.PKCS11Session) error {
		k, err = GenerateECDSAKeyPairOnSession(session, slots[0], keyNameBytes, keyNameBytes, elliptic.P256())
		return err
	})
	return k, k.PubKey.(*ecdsa.PublicKey), nil
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

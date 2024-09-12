package main

import (
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
	conf := crypto11.PKCS11Config {
		Path: os.Args[1],
	}
	ctx, err := crypto11.Configure(&conf)
	if err != nil {
		log.Fatal(err)
	}
	if ctx != nil {
	}

	switch os.Args[2] {
		// all of the different things we need to test
		case "generate-ecdsa":
			testGenerateEcdsa(ctx)
		case "rand-reader":
			testRandReader(ctx)
		case "find-keypair":
			testFindKeyPair(ctx)
		case "all":
			testGenerateEcdsa(ctx)
			testRandReader(ctx)
			testFindKeyPair(ctx)
	}
}

func testGenerateEcdsa(ctx *pkcs11.Ctx) error {
	return nil
}

func testRandReader(ctx *pkcs11.Ctx) error {
	return nil
}

func testFindKeyPair(ctx *pkcs11.Ctx) error {
	return nil
}

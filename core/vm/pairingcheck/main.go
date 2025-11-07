package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

const (
	inputHex = "0000000000000000000000000000000010b93b3ff2351cc019178b142ecb2eed17b0c99c2b6e9c30bedae8cfc26f8f7cdf75b9f0dbb2ea31e11117a04dbe962f00000000000000000000000000000000074a926af04042ab5876a9ba4297a806a34732d7df7a33b2d34d8e77313c34c49f365eba61e923acfbdfa160c3e51d2700000000000000000000000000000000172bd82fd5a7f267a7dcacdaba4b84c855a12023a4cb71bf86567332b13cea64702197d2486186d9a1dd6aef20982406000000000000000000000000000000000a462bde30747207cfea7934193e74a7e852460662c6df5a9347461cdd5314fd952af1415a8173b4b41ed7d582f6d7a70000000000000000000000000000000010a167b4633f9c830bbd148efc88cefed2a62699e447874e4470fbb30e3be372991088585be0d2a0b9ab4139ab6bf701000000000000000000000000000000000c4dd45200aca88154aae4bac59a69267f65b4958594b0928967bfd76e26afae5713ac94cd2a10337c313e3b8739d5bb0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca000000000000000000000000000000000d3d6ec6a9b1abb9e6cd86df330080a546d2b8599950618eb76efbdfe13ef74fc14e4fa9919bd440dd2bd02bf84421af000000000000000000000000000000000cb7f52fa291c273810bcf0dd1d3dc41e0449e6da4ff2b90243ce33b6ff4733cbd3f8446878109e369db1ae9a67622430000000000000000000000000000000010c55d7516d586441d7dd978e199f08383013aa6e3b2f9a48ac3366e9a5df7a003786b93b937d9ccf463a6f10b34230600000000000000000000000000000000089653aef1a209f9bbf2837562b02adc6e766753e0247417225a4de4ad095ad50d619b719e234702df7f87e8cd548733"
)

var (
	errBLS12381InvalidInputLength          = errors.New("invalid input length")
	errBLS12381InvalidFieldElementTopBytes = errors.New("invalid field element top bytes")
	errBLS12381G1PointSubgroup             = errors.New("g1 point is not on correct subgroup")
	errBLS12381G2PointSubgroup             = errors.New("g2 point is not on correct subgroup")
)

func run(input []byte) ([]byte, error) {
	// Implements EIP-2537 Pairing precompile logic.
	// > Pairing call expects `384*k` bytes as an inputs that is interpreted as byte concatenation of `k` slices. Each slice has the following structure:
	// > - `128` bytes of G1 point encoding
	// > - `256` bytes of G2 point encoding
	// > Output is a `32` bytes where last single byte is `0x01` if pairing result is equal to multiplicative identity in a pairing target field and `0x00` otherwise
	// > (which is equivalent of Big Endian encoding of Solidity values `uint256(1)` and `uin256(0)` respectively).
	k := len(input) / 384
	if len(input) == 0 || len(input)%384 != 0 {
		return nil, errBLS12381InvalidInputLength
	}

	var (
		p []bls12381.G1Affine
		q []bls12381.G2Affine
	)

	// Decode pairs
	for i := 0; i < k; i++ {
		off := 384 * i
		t0, t1, t2 := off, off+128, off+384

		// Decode G1 point
		p1, err := decodePointG1(input[t0:t1])
		if err != nil {
			errString := fmt.Sprintf("invalid point. Not on G2 curve. i=%d, input=\"%s\"", i, hex.EncodeToString(input[t0:t1]))
			return nil, errors.New(errString)
		}
		// Decode G2 point
		p2, err := decodePointG2(input[t1:t2])
		if err != nil {
			errString := fmt.Sprintf("invalid point. Not on G2 curve. i=%d, input=\"%s\"", i, hex.EncodeToString(input[t1:t2]))
			return nil, errors.New(errString)
		}

		// 'point is on curve' check already done,
		// Here we need to apply subgroup checks.
		if !p1.IsInSubGroup() {
			return nil, errBLS12381G1PointSubgroup
		}
		if !p2.IsInSubGroup() {
			return nil, errBLS12381G2PointSubgroup
		}
		p = append(p, *p1)
		q = append(q, *p2)
	}
	// Prepare 32 byte output
	out := make([]byte, 32)

	// Compute pairing and set the result
	ok, err := bls12381.PairingCheck(p, q)
	if err == nil && ok {
		out[31] = 1
	}
	return out, nil
}

func decodePointG1(in []byte) (*bls12381.G1Affine, error) {
	if len(in) != 128 {
		return nil, errors.New("invalid g1 point length")
	}
	// decode x
	x, err := decodeBLS12381FieldElement(in[:64])
	if err != nil {
		return nil, err
	}
	// decode y
	y, err := decodeBLS12381FieldElement(in[64:])
	if err != nil {
		return nil, err
	}
	elem := bls12381.G1Affine{X: x, Y: y}
	if !elem.IsOnCurve() {
		return nil, errors.New("invalid point: not on curve G1")
	}

	return &elem, nil
}

// decodePointG2 given encoded (x, y) coordinates in 256 bytes returns a valid G2 Point.
func decodePointG2(in []byte) (*bls12381.G2Affine, error) {
	if len(in) != 256 {
		return nil, errors.New("invalid g2 point length")
	}
	x0, err := decodeBLS12381FieldElement(in[:64])
	if err != nil {
		return nil, err
	}
	x1, err := decodeBLS12381FieldElement(in[64:128])
	if err != nil {
		return nil, err
	}
	y0, err := decodeBLS12381FieldElement(in[128:192])
	if err != nil {
		return nil, err
	}
	y1, err := decodeBLS12381FieldElement(in[192:])
	if err != nil {
		return nil, err
	}

	p := bls12381.G2Affine{X: bls12381.E2{A0: x0, A1: x1}, Y: bls12381.E2{A0: y0, A1: y1}}
	if !p.IsOnCurve() {
		return nil, errors.New("invalid point: not on curve G2")
	}
	return &p, err
}

// decodeBLS12381FieldElement decodes BLS12-381 elliptic curve field element.
// Removes top 16 bytes of 64 byte input.
func decodeBLS12381FieldElement(in []byte) (fp.Element, error) {
	if len(in) != 64 {
		return fp.Element{}, errors.New("invalid field element length")
	}
	// check top bytes
	for i := 0; i < 16; i++ {
		if in[i] != byte(0x00) {
			return fp.Element{}, errBLS12381InvalidFieldElementTopBytes
		}
	}
	var res [48]byte
	copy(res[:], in[16:])

	return fp.BigEndian.Element(&res)
}

func main() {
	inputBytes, err := hex.DecodeString(inputHex)
	if err != nil {
		log.Fatal(err)
	}
	res, err := run(inputBytes)
	if err != nil {
		log.Fatal("precompile err: ", err)
	}
	log.Printf("precompile result: %s\n", hex.EncodeToString(res))
}

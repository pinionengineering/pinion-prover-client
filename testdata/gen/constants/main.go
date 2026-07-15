// Prints BN256 curve constants needed to implement the pairing in JavaScript.
// Run with: go run .
package main

import (
	"fmt"
	"math/big"

	"github.com/cloudflare/bn256"
)

func bigFromBase10(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 10)
	return n
}

func main() {
	p := bigFromBase10("65000549695646603732796438742359905742825358107623003571877145026864184071783")

	// G1 generator (1, -2 mod p).
	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	fmt.Printf("G1 generator (affine):\n  %s\n\n", g1.String())

	// G2 generator (twist point).
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	fmt.Printf("G2 generator (affine):\n  %s\n\n", g2.String())

	// Field prime and group order.
	fmt.Printf("Field prime p:\n  %s\n\n", p.String())
	fmt.Printf("Group order n:\n  %s\n\n", bn256.Order.String())

	// Twist b coefficient: 3 / (3+i) in Fp2.
	// = 3 * (3+i)^(-1) in Fp2 = Fp[u]/(u²+1)
	// (3+i)^(-1) = (3-i) / (3² + 1²) = (3-i)/10
	// So 3/(3+i) = 9/10 - 3i/10
	inv10 := new(big.Int).ModInverse(big.NewInt(10), p)
	twistBRe := new(big.Int).Mul(big.NewInt(9), inv10)
	twistBRe.Mod(twistBRe, p)
	twistBIm := new(big.Int).Mul(big.NewInt(-3), inv10) // = p - 3/10
	twistBIm.Mod(twistBIm, p)
	fmt.Printf("Twist b = 3/(3+i):\n  Re: %s\n  Im: %s\n\n", twistBRe.Text(10), twistBIm.Text(10))

	// G2 generator: cloudflare's String() prints (im, re) for each coordinate.
	// Parse the hex values to bigints.
	g2xIm, _ := new(big.Int).SetString("2ecca446ff6f3d4d03c76e9b5c752f28bc37b364cb05ac4a37eb32e1c3245970", 16)
	g2xRe, _ := new(big.Int).SetString("8f25386f72c9462b81597d65ae2092c4b97792155dcdaad32b8a6dd41792534c", 16)
	g2yIm, _ := new(big.Int).SetString("2db10ef5233b0fe3962b9ee6a4bbc2b5bde01a54f3513d42df972e128f31bf12", 16)
	g2yRe, _ := new(big.Int).SetString("274e5747e8cafacc3716cc8699db79b22f0e4ff3c23e898f694420a3be3087a5", 16)
	fmt.Printf("G2 generator decimal coords (noble Fp2: c0=real, c1=imaginary):\n")
	fmt.Printf("  Gx.c0 (real): %s\n", g2xRe.Text(10))
	fmt.Printf("  Gx.c1 (imag): %s\n", g2xIm.Text(10))
	fmt.Printf("  Gy.c0 (real): %s\n", g2yRe.Text(10))
	fmt.Printf("  Gy.c1 (imag): %s\n", g2yIm.Text(10))

	// G1 generator y = p - 2
	g1y := new(big.Int).Sub(p, big.NewInt(2))
	fmt.Printf("\nG1 generator:\n  Gx: 1\n  Gy: %s\n", g1y.Text(10))

	// BN parameter u for 6u+2 Miller loop
	u := bigFromBase10("6518589491078791937")
	loopSize := new(big.Int).Add(new(big.Int).Mul(big.NewInt(6), u), big.NewInt(2))
	fmt.Printf("\nAte loop size (6u+2): %s\n", loopSize.Text(10))
	fmt.Printf("u bit length: %d\n", u.BitLen())
}

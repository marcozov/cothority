package lib

import (
	
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/nist"
	//"github.com/lihiid/Crypto/abstract"
	//"github.com/lihiid/Crypto/nist"
	"gopkg.in/dedis/crypto.v0/random"
	"testing"
)

func TestCU(t *testing.T) {

	suite := nist.NewAES128SHA256P256()
	var c1 *PPSI
	var c2 *PPSI
	var c3 *PPSI

	var rep *PPSI

	a := suite.Scalar().Pick(random.Stream)
	A := suite.Point().Mul(nil, a)
	b := suite.Scalar().Pick(random.Stream)
	B := suite.Point().Mul(nil, b)
	c := suite.Scalar().Pick(random.Stream)
	C := suite.Point().Mul(nil, c)

	d := suite.Scalar().Pick(random.Stream)
	//		D := suite.Point().Mul(nil, d)

	set11 := []string{"543323345", "543323045", "843323345"}

	publics := []abstract.Point{A, B, C}
	private1 := a
	private2 := b
	private3 := c
	private4 := d

	c1 = NewPPSI3(suite, private1, publics, 3)
	c2 = NewPPSI3(suite, private2, publics, 3)
	c3 = NewPPSI3(suite, private3, publics, 3)
	rep = NewPPSI3(suite, private4, publics, 3)

	//	var set1,set2,set3 []map[int]abstract.Point
	var set4, set5, set6, set7 []abstract.Point
	var set8 []string
	var set0 []map[int]abstract.Point

	set0 = rep.EncryptionOneSetOfPhones(set11, 3)

	c1.numOfThreads=1
	c2.numOfThreads=1
	c3.numOfThreads=1
	set1 := c1.DecryptElgEncryptPH(set0, 0)
	set2 := c2.DecryptElgEncryptPH(set1, 1)
	set3 := c3.DecryptElgEncryptPH(set2, 2)
	set4 = c3.ExtractPHEncryptions(set3)
	//fmt.Printf("%v\n",   set4)

	set5 = c3.DecryptPH(set4)
	set6 = c1.DecryptPH(set5)
	set7 = c2.DecryptPH(set6)

	set8 = c2.ExtractPlains(set7)
	println("Decryption : " + set8[0])
	println("Decryption : " + set8[1])
	println("Decryption : " + set8[2])

}



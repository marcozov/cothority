package lib


import (
	"gopkg.in/dedis/crypto.v0/abstract"
	//"github.com/lihiid/Crypto/abstract"
	"gopkg.in/dedis/crypto.v0/random"
)

type PH struct {
	encKey abstract.Scalar
	decKey abstract.Scalar
	suite  abstract.Suite
}

func NewPH(suite abstract.Suite) *PH {
	ph := &PH{
		suite: suite,
	}
	ph.createKeys()
	return ph
}


//Create encryption and decryption keys
func (c *PH) createKeys() {

	//b:=c.suite.Scalar().Zero()
	enckey := c.suite.Scalar().Pick(random.Stream)

	//for !c.suite.Scalar().Gcd(enckey,b).Equal(c.suite.Scalar().One()) {
		enckey = c.suite.Scalar().Pick(random.Stream)
	//}

	c.encKey = enckey
	c.decKey = c.suite.Scalar().Inv(enckey)

}

//Decrypt with Pohlig Hellman, output is a string
func (c *PH) PHDecrypt(cipher abstract.Point) (
	message string) {

	var bytemessage []byte

	S := c.suite.Point().Mul(cipher, c.decKey)
	bytemessage, _ = S.Data()
	message = string(bytemessage)

	return

}

//Encrypt with Pohlig Hellman, input is []byte
func (c *PH) PHEncrypt(message []byte) (
	S abstract.Point) {

	M, _ := c.suite.Point().Pick(message, random.Stream)
	S = c.suite.Point().Mul(M, c.encKey)
	return
}

//Decrypt with Pohlig Hellman, output is a point
func (c *PH) PartialPHDecrypt(cipher abstract.Point) (
	S abstract.Point) {

	S = c.suite.Point().Mul(cipher, c.decKey)
	return

}

//Encrypt with Pohlig Hellman, input is a point
func (c *PH) PartialPHEncrypt(M abstract.Point) (
	S abstract.Point) {

	S = c.suite.Point().Mul(M, c.encKey)
	return
}

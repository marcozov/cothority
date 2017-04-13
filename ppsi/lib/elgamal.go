package lib

import (
	"gopkg.in/dedis/crypto.v0/abstract"
	//"github.com/lihiid/Crypto/abstract"
	"gopkg.in/dedis/crypto.v0/random"
)


//performs elgamal encryption of a message, with the following invariant:
//forall message1, message2, if message1==message2 --> M1==M2(two identical messages are encoded into two identical points)
func ElGamalEncrypt(suite abstract.Suite, pubkey abstract.Point, message []byte) (
	K, C abstract.Point, remainder []byte) {

	seed := []byte{1, 1, 1, 1}
	cip := suite.Cipher(seed)
	M, remainder := suite.Point().Pick(message, cip)
	k := suite.Scalar().Pick(random.Stream)
	K = suite.Point().Mul(nil, k)
	S := suite.Point().Mul(pubkey, k)
	C = S.Add(S, M)
	return
}

//performs elgamal encryption of a message
func NonSeededElGamalEncrypt(suite abstract.Suite, pubkey abstract.Point, message []byte) (
	K, C abstract.Point, remainder []byte) {

	M, remainder := suite.Point().Pick(message, random.Stream)
	k := suite.Scalar().Pick(random.Stream)
	K = suite.Point().Mul(nil, k)
	S := suite.Point().Mul(pubkey, k)
	C = S.Add(S, M)
	return
}

//performs elgamal encryption of a point
func PartialElGamalEncrypt(suite abstract.Suite, pubkey abstract.Point, M abstract.Point) (
	K, C abstract.Point, remainder []byte) {

	k := suite.Scalar().Pick(random.Stream)
	K = suite.Point().Mul(nil, k)
	S := suite.Point().Mul(pubkey, k)
	C = S.Add(S, M)
	
	return
}
	
//pefroms elgamal decryption, output is a message
func ElGamalDecrypt(suite abstract.Suite, prikey abstract.Scalar, K, C abstract.Point) (
	message []byte, err error) {

	S := suite.Point().Mul(K, prikey)
	M := suite.Point().Sub(C, S)
	message, err = M.Data()
	return
}

//performs elgamal decryption, output is a point
func PartialElGamalDecrypt(suite abstract.Suite, prikey abstract.Scalar, K, C abstract.Point) (
	M abstract.Point, err error) {

	S := suite.Point().Mul(K, prikey)
	M = suite.Point().Sub(C, S)
	_, err = M.Data()
	return
}


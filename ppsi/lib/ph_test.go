package lib


import (
	"testing"
	"gopkg.in/dedis/crypto.v0/nist"
	//"github.com/lihiid/Crypto/nist"
)

func TestPH(t *testing.T) {

	var c1 *PH
	suite := nist.NewAES128SHA256P256()
	c1 = NewPH(suite)
	message := []byte("Pohlig Hellman")
	cipher := c1.PHEncrypt(message)
	encmessage := c1.PHDecrypt(cipher)

	if string(message) != string(encmessage) {
		panic("decryption produced wrong output: " + string(encmessage))
	}
  
	println("Decryption succeeded: " + string(encmessage))

}

package lib

import (
	
	"gopkg.in/dedis/crypto.v0/abstract"
	//"github.com/lihiid/Crypto/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"math/rand"
	"sync"
)

type PPSI struct {
	EncryptedSets [][]map[int]abstract.Point
	ids           int
	encKey        abstract.Scalar
	decKey        abstract.Scalar
	suite         abstract.Suite
	publics       []abstract.Point
	private       abstract.Scalar
	UpdatedSet    []map[int]abstract.Point
	numOfThreads  int
}

func NewPPSI(suite abstract.Suite, private abstract.Scalar, publics []abstract.Point, ids int, numOfThreads int) *PPSI {
	ppsi := &PPSI{
		suite:        suite,
		private:      private,
		publics:      publics,
		numOfThreads: numOfThreads,
	}
	ppsi.ids = ids
	ppsi.createKeys()
	return ppsi
}

func NewPPSI3(suite abstract.Suite, private abstract.Scalar, publics []abstract.Point, ids int) *PPSI {
	ppsi := &PPSI{
		suite:   suite,
		private: private,
		publics: publics,
	}
	ppsi.ids = ids
	ppsi.createKeys()
	return ppsi
}

func NewPPSI2(suite abstract.Suite, publics []abstract.Point, ids int) *PPSI {
	ppsi := &PPSI{
		suite: suite,

		publics: publics,
	}
	ppsi.ids = ids
	ppsi.createKeys()
	return ppsi
}

func (c *PPSI) initPPSI(numPhones int, ids int) {
	//		c.EncryptedPhoneSet =  make([]map[int]abstract.Point, numPhones)
	c.ids = ids

}

//Given several sets of messags, elgamal encrypt each one multiple times-"ids" times, each time with the
//public key of a diffrent user
func (c *PPSI) EncryptPhones(setsToEncrypt [][]string, ids int) [][]map[int]abstract.Point {

	c.EncryptedSets = make([][]map[int]abstract.Point, ids)
	for i := 0; i < len(setsToEncrypt); i++ {
		out := c.EncryptionOneSetOfPhones(setsToEncrypt[i], ids)
		c.EncryptedSets[i] = out
		//	 fmt.Printf("%v\n",   c.EncryptedSets[i])
	}

	return c.EncryptedSets
}

func (c *PPSI) Shuffle(src []map[int]abstract.Point) []map[int]abstract.Point {

	dst := make([]map[int]abstract.Point, len(src))
	perm := rand.Perm(len(src))
	for i, v := range perm {
		dst[v] = src[i]
	}

	return dst
}

//Given one messaege, elgamal encrypt it multiple times-"ids" times, each time with
//the public key of a different user
func (c *PPSI) MultipleElgEncryption(message string, ids int) (
	cipher map[int]abstract.Point) {

	cipher = make(map[int]abstract.Point)
	messageByte := []byte(message)

	K, C, _ := ElGamalEncrypt(c.suite, c.publics[0], messageByte)
	cipher[0] = K
	cipher[-1] = C

	for v := 1; v < ids; v++ {
		data := cipher[-1]
		K, C, _ := PartialElGamalEncrypt(c.suite, c.publics[v], data)
		cipher[v] = K
		cipher[-1] = C

	}

	return cipher

}

//Given one set of messages, elgamal encrypt each one multiple times-"ids" times,
//each time with the public key of a different user
func (c *PPSI) EncryptionOneSetOfPhones(set []string, ids int) (
	EncryptedPhoneSet []map[int]abstract.Point) {

	EncryptedPhoneSet = make([]map[int]abstract.Point, len(set))
	for v := 0; v < len(set); v++ {
		cipher := c.MultipleElgEncryption(set[v], ids)
		EncryptedPhoneSet[v] = cipher

	}

	return

}

//Given one set of ciphers, for each cipher, performs an elgamal decryption with the user "id" private key,
//and Phoilg Hellman encryption with the user's "id" PH key
func (c *PPSI) DecryptElgEncryptPH(set []map[int]abstract.Point, id int) (
	newSet []map[int]abstract.Point) {

	c.UpdatedSet = make([]map[int]abstract.Point, len(set))
	c.UpdatedSet = set
	var wg sync.WaitGroup

	var ciphersToThread = len(set) / c.numOfThreads

	for i := 0; i < c.numOfThreads; i++ {

		wg.Add(1)
		if i == c.numOfThreads-1 {
			go c.DecryptElgEncryptPHworker(&wg, i, id, i*ciphersToThread, len(set), set)
		}
		if i != c.numOfThreads-1 {
			go c.DecryptElgEncryptPHworker(&wg, i, id, i*ciphersToThread, (i*ciphersToThread)+ciphersToThread, set)
		}

	}

	wg.Wait()
	c.UpdatedSet = c.Shuffle(c.UpdatedSet)
	newSet = c.UpdatedSet
	return
}

func (c *PPSI) DecryptElgEncryptPHworker(wg *sync.WaitGroup, id int, idd int, start int, end int, set []map[int]abstract.Point) {
	defer wg.Done()

	//fmt.Printf("Worker %v: Started\n", id)

	for ii := start; ii < end; ii++ {

		cipher := set[ii]
		K := cipher[idd]

		C := cipher[-1]
		resElg, _ := PartialElGamalDecrypt(c.suite, c.private, K, C)

		resPH := c.PHEncrypt(resElg)

		c.UpdatedSet[ii][-1] = resPH

		for j := 0; j < c.ids; j++ {
			res2PH := c.PHEncrypt(cipher[j])
			c.UpdatedSet[ii][j] = res2PH
		}
	}
	//fmt.Printf("Worker %v: Finished\n", id)
}

//Extracts the ciphers themselves from a map to a slice
func (c *PPSI) ExtractPHEncryptions(set []map[int]abstract.Point) (
	encryptedPH []abstract.Point) {
	encryptedPH = make([]abstract.Point, len(set))

	for i := 0; i < len(set); i++ {
		cipher := set[i]
		encryptedPH[i] = cipher[-1]

	}
	return
}

//Performs a partial pohig hellman decryption-the input is a message which is encrypted by 2 or more users' keys,
//and the output is the message after one layer of decryption was removed and it is still encrypted
//by 1 or more user's keys
func (c *PPSI) DecryptPH(set []abstract.Point) (UpdatedSet []abstract.Point) {

	UpdatedSet = make([]abstract.Point, len(set))
	UpdatedSet = set

	for i := 0; i < len(UpdatedSet); i++ {
		resPH := c.PHDecrypt(UpdatedSet[i])
		UpdatedSet[i] = resPH
	}

	return
}

//Extracts the plains  to a slice
func (c *PPSI) ExtractPlains(set []abstract.Point) (
	plain []string) {
	plain = make([]string, len(set))

	var byteMessage []byte
	var message string

	for i := 0; i < len(set); i++ {
		byteMessage, _ = set[i].Data()
		message = string(byteMessage)
		plain[i] = message

	}

	return

}


//Create encryption and decryption keys
func (c *PPSI) createKeys() {

	//b:=c.suite.Scalar().Zero()
	enckey := c.suite.Scalar().Pick(random.Stream)

	//for !c.suite.Scalar().Gcd(enckey,b).Equal(c.suite.Scalar().One()) {
		enckey = c.suite.Scalar().Pick(random.Stream)
	//}

	c.encKey = enckey
	c.decKey = c.suite.Scalar().Inv(enckey)

}

//Decrypt with PH, input is a point
func (c *PPSI) PHDecrypt(cipher abstract.Point) (
	S abstract.Point) {

	S = c.suite.Point().Mul(cipher, c.decKey)
	return

}

//Encrypt with PH, input is a point
func (c *PPSI) PHEncrypt(M abstract.Point) (
	S abstract.Point) {

	S = c.suite.Point().Mul(M, c.encKey)
	return
}

package randhound_test

import (
	"testing"
	"time"

	"github.com/dedis/cothority/randhound"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
)

func TestRandHound(test *testing.T) {

	var name = "RandHound"
	var nodes int = 28
	var groups int = 4
	var purpose string = "RandHound test run"

	local := onet.NewLocalTest()
	_, _, tree := local.GenTree(int(nodes), true)
	defer local.CloseAll()

	log.Lvlf1("RandHound - starting")
	protocol, err := local.CreateProtocol(name, tree)
	if err != nil {
		test.Fatal("Couldn't initialise RandHound protocol:", err)
	}
	rh := protocol.(*randhound.RandHound)
	err = rh.Setup(nodes, groups, purpose)
	if err != nil {
		test.Fatal("Couldn't initialise RandHound protocol:", err)
	}
	if err := protocol.Start(); err != nil {
		test.Fatal(err)
	}

	select {
	case <-rh.Done:
		log.Lvlf1("RandHound - done")

		random, transcript, err := rh.Random()
		if err != nil {
			test.Fatal(err)
		}
		log.Lvlf1("RandHound - collective randomness: ok")

		_ = random
		_ = transcript

		log.Lvlf1("RandHound - collective randomness: %v", random)

		//err = rh.Verify(rh.Suite(), random, transcript)
		//if err != nil {
		//	test.Fatal(err)
		//}
		//log.Lvlf1("RandHound - verification: ok")

	case <-time.After(time.Second * time.Duration(nodes) * 2):
		test.Fatal("RandHound – time out")
	}
}

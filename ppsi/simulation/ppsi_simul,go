package main

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/dedis/cothority/ppsi"
	"github.com/dedis/cothority/ppsi/lib"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/dedis/onet/simul"
	"github.com/dedis/onet/simul/monitor"
)

func init() {
	onet.SimulationRegister("PPSI", NewSimulation)
}

type Simulation struct {
	onet.SimulationBFTree
}

func NewSimulation(config string) (onet.Simulation, error) {
	jvs := &Simulation{}
	_, err := toml.Decode(config, jvs)
	if err != nil {
		return nil, err
	}
	return jvs, nil
}

// Setup configures a JVSS simulation
func (jvs *Simulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	sim := new(onet.SimulationConfig)
	jvs.CreateRoster(sim, hosts, 2000)
	err := jvs.CreateTree(sim)
	return sim, err
}

func (jvs *Simulation) Run(config *onet.SimulationConfig) error {

	set1 := []string{"543323345", "543323045", "843323345", "213323045", "843323345"}
	set2 := []string{"543323345", "543323045", "843343345", "213323045", "843323345"}
	set3 := []string{"543323345", "543323045", "843323345", "213323045", "843323345"}
	set4 := []string{"543323345", "543323045", "843333345", "548323032", "213323045"}
	set5 := []string{"543323345", "543323045", "843323345", "543323245", "213323045"}
	set6 := []string{"543323345", "543323045", "843333345", "543323032", "213323045"}

	setsToEncrypt := [][]string{set1, set2, set3, set4, set5, set6}

	suite := network.Suite
	publics := config.Roster.Publics()
	ppsii := lib.NewPPSI2(suite, publics, 6)
	EncPhones := ppsii.EncryptPhones(setsToEncrypt, 6)

	randM := monitor.NewTimeMeasure("round")

	client, err := config.Overlay.CreateProtocol("PPSI", config.Tree, onet.NilServiceID)
	if err != nil {
		return err
	}
	var rh *ppsi.PPSI
	
	rh = client.(*ppsi.PPSI)
	rh.EncryptedSets = EncPhones
	
	if err := rh.Start(); err != nil {
		log.Error("Error while starting protcol:", err)
	}

	done := make(chan bool)
	fn := func() {
		done <- true
	}
	rh.RegisterSignatureHook(fn)
	if err := rh.Start(); err != nil {
		log.Error("Error while starting protcol:", err)
	}

	select {
	case <-done:
		log.Lvlf1("Finished one round of ppsi")
		if rh.Status == 0 {
			fmt.Printf("The intersection was sucessfully decrypted: ")
		}
		if rh.Status == 1 {
			fmt.Printf("Illegal intersection")
		}
		randM.Record()

	}

	return nil
}

func main() {
	simul.Start()
}

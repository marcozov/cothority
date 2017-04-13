package main

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/lihiid/ppsi/protocol"
	"github.com/lihiid/ppsi/lib"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/dedis/onet.v1/simul/monitor"
	"gopkg.in/dedis/onet.v1/simul"
	"os"
	"bufio"
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


func (jvs *Simulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	sim := new(onet.SimulationConfig)
	jvs.CreateRoster(sim, hosts, 2000)
	err := jvs.CreateTree(sim)
	return sim, err
}

func (jvs *Simulation) Run(config *onet.SimulationConfig) error {

	set1, _ := readSets("../set1.txt")
	set2, _ := readSets("../set2.txt")
	set3, _ := readSets("../set3.txt")
	set4, _ := readSets("../set4.txt")
	set5, _ := readSets("../set5.txt")
	set6, _ := readSets("../set6.txt")
	
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
	var rh *protocol.PPSI
	
	rh = client.(*protocol.PPSI)
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

func readSets(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("%v\n", err)
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}

/*
 * The SkipChainManager can handle root- and configuration-skipchains
 * in a hierarchical setup.
 * For normal usage, you set up a root-skipchain that is responsible for
 * slow changes (a couple of times a year).
 * The root-skipchain delegates trust to a configuration-skipchain that can
 * track faster changes in the cothority.
 */
package main

import (
	"os"

	"github.com/dedis/cothority/log"
	"gopkg.in/urfave/cli.v1"
)

func main() {
	app := cli.NewApp()
	app.Name = "scmgr"
	app.Usage = "Manage root- and cfg-skipchains."
	app.Version = "0.1"
	app.Commands = []cli.Command{
		{
			Name:    "root",
			Aliases: []string{"r"},
			Usage:   "handle root skipchain",
			Subcommands: []cli.Command{
				{
					Name:      "create",
					Aliases:   []string{"c"},
					ArgsUsage: "roster-file",
					Action:    rootCreate,
				},
				{
					Name:    "list",
					Aliases: []string{"ls"},
					Action:  rootList,
				},
			},
		},
	}
	app.Flags = []cli.Flag{
		cli.IntFlag{
			Name:  "debug, d",
			Value: 0,
			Usage: "debug-level: 1 for terse, 5 for maximal",
		},
		cli.StringFlag{
			Name:  "config, c",
			Value: "~/.scmgr",
			Usage: "The configuration-directory of scmgr",
		},
	}
	app.Before = func(c *cli.Context) error {
		log.SetDebugVisible(c.Int("debug"))
		return nil
	}
	app.Run(os.Args)

}

// Main command.
func rootList(c *cli.Context) error {
	log.Info("Main command")
	return nil
}
func rootCreate(c *cli.Context) error {
	log.Info("Main command")
	return nil
}

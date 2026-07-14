//go:build !synology

package main

import "testing"

func TestDefaultBuildExcludesSynologyCommand(t *testing.T) {
	for _, command := range rootCmd.Commands() {
		if command.Name() == "synology" {
			t.Fatal("default build unexpectedly includes the synology command")
		}
	}
}

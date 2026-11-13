// Command opencm is the OpenCM command-line client. It talks exclusively to the
// public REST API (see server/openapi.yaml).
package main

import (
	"os"

	"github.com/opencm/opencm/cli/internal/cmd"
)

func main() {
	os.Exit(cmd.Execute())
}

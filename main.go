// Command attackscout-agent checks a website from inside its server: versions
// and end of life, CVEs, exposed files, permissions, web server headers,
// wp-config.php and certificates. It only reads, and sends nothing over the
// network unless asked to ("db update", "--online").
package main

import (
	"os"

	"github.com/attackscout/attackscout-agent/internal/cli"
)

func main() { os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr)) }

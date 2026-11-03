// Package migrations embeds the schema so the server binary can apply it
// without files on disk.
package migrations

import "embed"

//go:embed postgres/*.sql
var Postgres embed.FS

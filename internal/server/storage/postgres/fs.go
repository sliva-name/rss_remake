package postgres

import (
	"embed"
	"io/fs"
)

func subFS(files embed.FS, directory string) fs.FS {
	sub, err := fs.Sub(files, directory)
	if err != nil {
		// fs.Sub fails only on an invalid path, which is a compile-time constant.
		panic(err)
	}
	return sub
}

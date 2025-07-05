package pkg

import (
	"github.com/anchore/syft/syft/source"
	"github.com/stefanb/grype/grype/distro"
)

type Context struct {
	Source *source.Description
	Distro *distro.Distro
}

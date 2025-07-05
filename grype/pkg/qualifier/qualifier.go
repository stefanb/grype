package qualifier

import (
	"github.com/stefanb/grype/grype/pkg"
)

type Qualifier interface {
	Satisfied(p pkg.Package) (bool, error)
}

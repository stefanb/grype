package stock

import (
	"strings"

	grypePkg "github.com/stefanb/grype/grype/pkg"
)

type Resolver struct {
}

func (r *Resolver) Normalize(name string) string {
	return strings.ToLower(name)
}

func (r *Resolver) Resolve(p grypePkg.Package) []string {
	return []string{r.Normalize(p.Name)}
}

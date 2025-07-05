package portage

import (
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/stefanb/grype/grype/match"
	"github.com/stefanb/grype/grype/matcher/internal"
	"github.com/stefanb/grype/grype/pkg"
	"github.com/stefanb/grype/grype/vulnerability"
)

type Matcher struct {
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.PortagePkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.PortageMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	return internal.MatchPackageByDistro(store, p, nil, m.Type())
}

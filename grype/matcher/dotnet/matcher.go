package dotnet

import (
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/stefanb/grype/grype/match"
	"github.com/stefanb/grype/grype/matcher/internal"
	"github.com/stefanb/grype/grype/pkg"
	"github.com/stefanb/grype/grype/vulnerability"
)

type Matcher struct {
	cfg MatcherConfig
}

type MatcherConfig struct {
	UseCPEs bool
}

func NewDotnetMatcher(cfg MatcherConfig) *Matcher {
	return &Matcher{
		cfg: cfg,
	}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.DotnetPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.DotnetMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	return internal.MatchPackageByEcosystemAndCPEs(store, p, m.Type(), m.cfg.UseCPEs)
}

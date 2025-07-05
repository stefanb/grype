package v5

import (
	"github.com/stefanb/grype/grype/match"
	"github.com/stefanb/grype/grype/vulnerability"
)

type ProviderStore struct {
	vulnerability.Provider
	match.ExclusionProvider
}

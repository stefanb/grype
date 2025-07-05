package java

import (
	"fmt"
	"strings"

	"github.com/anchore/packageurl-go"
	grypePkg "github.com/stefanb/grype/grype/pkg"
	"github.com/stefanb/grype/internal/log"
	"github.com/stefanb/grype/internal/stringutil"
)

type Resolver struct {
}

func (r *Resolver) Normalize(name string) string {
	return strings.ToLower(name)
}

func (r *Resolver) Resolve(p grypePkg.Package) []string {
	names := stringutil.NewStringSet()

	// The current default for the Java ecosystem is to use a Maven-like identifier of the form
	// "<group-name>:<artifact-name>"
	if metadata, ok := p.Metadata.(grypePkg.JavaMetadata); ok {
		if metadata.PomGroupID != "" {
			if metadata.PomArtifactID != "" {
				names.Add(r.Normalize(fmt.Sprintf("%s:%s", metadata.PomGroupID, metadata.PomArtifactID)))
			}
			if metadata.ManifestName != "" {
				names.Add(r.Normalize(fmt.Sprintf("%s:%s", metadata.PomGroupID, metadata.ManifestName)))
			}
		}
	}

	if p.PURL != "" {
		purl, err := packageurl.FromString(p.PURL)
		if err != nil {
			log.Warnf("unable to resolve java package identifier from purl=%q: %+v", p.PURL, err)
		} else {
			names.Add(r.Normalize(fmt.Sprintf("%s:%s", purl.Namespace, purl.Name)))
		}
	}

	return names.ToSlice()
}

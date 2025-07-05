package java

import (
	"context"
	"errors"

	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/stefanb/grype/grype/pkg"
	"github.com/stefanb/grype/grype/version"
	"github.com/stefanb/grype/grype/vulnerability"
	"github.com/stefanb/grype/grype/vulnerability/mock"
)

func newMockProvider() vulnerability.Provider {
	return mock.VulnerabilityProvider([]vulnerability.Vulnerability{
		{
			PackageName: "org.springframework.spring-webmvc",
			Constraint:  version.MustGetConstraint(">=5.0.0,<5.1.7", version.UnknownFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2014-fake-2", Namespace: "github:language:" + syftPkg.Java.String()},
		},
		{
			PackageName: "org.springframework.spring-webmvc",
			Constraint:  version.MustGetConstraint(">=5.0.1,<5.1.7", version.UnknownFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2013-fake-3", Namespace: "github:language:" + syftPkg.Java.String()},
		},
		// Package name is expected to resolve to <group-name>:<artifact-name> if pom groupID and artifactID is present
		// See JavaResolver.Names: https://github.com/stefanb/grype/blob/402067e958a4fa9d20384752351d6c54b0436ba1/grype/db/v6/name/java.go#L19
		{
			PackageName: "org.springframework:spring-webmvc",
			Constraint:  version.MustGetConstraint(">=5.0.0,<5.1.7", version.UnknownFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2014-fake-2", Namespace: "github:language:" + syftPkg.Java.String()},
		},
		{
			PackageName: "org.springframework:spring-webmvc",
			Constraint:  version.MustGetConstraint(">=5.0.1,<5.1.7", version.UnknownFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2013-fake-3", Namespace: "github:language:" + syftPkg.Java.String()},
		},
		// unexpected...
		{
			PackageName: "org.springframework.spring-webmvc",
			Constraint:  version.MustGetConstraint(">=5.0.0,<5.0.7", version.UnknownFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2013-fake-BAD", Namespace: "github:language:" + syftPkg.Java.String()},
		},
	}...)
}

type mockMavenSearcher struct {
	pkg                  pkg.Package
	simulateRateLimiting bool
}

func (m mockMavenSearcher) GetMavenPackageBySha(context.Context, string) (*pkg.Package, error) {
	if m.simulateRateLimiting {
		return nil, errors.New("you been rate limited")
	}
	return &m.pkg, nil
}

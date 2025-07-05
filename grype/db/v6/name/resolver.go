package name

import (
	syftPkg "github.com/anchore/syft/syft/pkg"
	grypePkg "github.com/stefanb/grype/grype/pkg"
)

type Resolver interface {
	Normalize(string) string
	Names(p grypePkg.Package) []string
}

func FromType(t syftPkg.Type) Resolver {
	switch t {
	case syftPkg.PythonPkg:
		return &PythonResolver{}
	case syftPkg.JavaPkg, syftPkg.JenkinsPluginPkg:
		return &JavaResolver{}
	}

	return nil
}

func PackageNames(p grypePkg.Package) []string {
	names := []string{p.Name}
	r := FromType(p.Type)
	if r == nil {
		return names
	}

	parts := r.Names(p)
	if len(parts) > 0 {
		names = parts
	}
	return names
}

func Normalize(name string, pkgType syftPkg.Type) string {
	r := FromType(pkgType)
	if r != nil {
		return r.Normalize(name)
	}
	return name
}

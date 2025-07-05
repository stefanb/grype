package matcher

import (
	"github.com/stefanb/grype/grype/match"
	"github.com/stefanb/grype/grype/matcher/apk"
	"github.com/stefanb/grype/grype/matcher/bitnami"
	"github.com/stefanb/grype/grype/matcher/dotnet"
	"github.com/stefanb/grype/grype/matcher/dpkg"
	"github.com/stefanb/grype/grype/matcher/golang"
	"github.com/stefanb/grype/grype/matcher/java"
	"github.com/stefanb/grype/grype/matcher/javascript"
	"github.com/stefanb/grype/grype/matcher/msrc"
	"github.com/stefanb/grype/grype/matcher/portage"
	"github.com/stefanb/grype/grype/matcher/python"
	"github.com/stefanb/grype/grype/matcher/rpm"
	"github.com/stefanb/grype/grype/matcher/ruby"
	"github.com/stefanb/grype/grype/matcher/rust"
	"github.com/stefanb/grype/grype/matcher/stock"
)

// Config contains values used by individual matcher structs for advanced configuration
type Config struct {
	Java       java.MatcherConfig
	Ruby       ruby.MatcherConfig
	Python     python.MatcherConfig
	Dotnet     dotnet.MatcherConfig
	Javascript javascript.MatcherConfig
	Golang     golang.MatcherConfig
	Rust       rust.MatcherConfig
	Stock      stock.MatcherConfig
}

func NewDefaultMatchers(mc Config) []match.Matcher {
	return []match.Matcher{
		&dpkg.Matcher{},
		ruby.NewRubyMatcher(mc.Ruby),
		python.NewPythonMatcher(mc.Python),
		dotnet.NewDotnetMatcher(mc.Dotnet),
		&rpm.Matcher{},
		java.NewJavaMatcher(mc.Java),
		javascript.NewJavascriptMatcher(mc.Javascript),
		&apk.Matcher{},
		golang.NewGolangMatcher(mc.Golang),
		&msrc.Matcher{},
		&portage.Matcher{},
		rust.NewRustMatcher(mc.Rust),
		stock.NewStockMatcher(mc.Stock),
		&bitnami.Matcher{},
	}
}

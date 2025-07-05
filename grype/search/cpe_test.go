package search

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cpe"
	"github.com/stefanb/grype/grype/vulnerability"
)

func Test_ByCPE(t *testing.T) {
	tests := []struct {
		name    string
		cpe     cpe.CPE
		input   vulnerability.Vulnerability
		wantErr require.ErrorAssertionFunc
		matches bool
		reason  string
	}{
		{
			name: "match",
			cpe:  cpe.Must("cpe:2.3:a:a-vendor:a-product:*:*:*:*:*:*:*:*", ""),
			input: vulnerability.Vulnerability{
				CPEs: []cpe.CPE{cpe.Must("cpe:2.3:a:a-vendor:a-product:*:*:*:*:*:*:*:*", "")},
			},
			matches: true,
		},
		{
			name: "not match",
			cpe:  cpe.Must("cpe:2.3:a:a-vendor:b-product:*:*:*:*:*:*:*:*", ""),
			input: vulnerability.Vulnerability{
				CPEs: []cpe.CPE{cpe.Must("cpe:2.3:a:a-vendor:a-product:*:*:*:*:*:*:*:*", "")},
			},
			matches: false,
			reason:  "CPE attributes do not match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constraint := ByCPE(tt.cpe)
			matches, reason, err := constraint.MatchesVulnerability(tt.input)
			wantErr := require.NoError
			if tt.wantErr != nil {
				wantErr = tt.wantErr
			}
			wantErr(t, err)
			assert.Equal(t, tt.matches, matches)
			assert.Equal(t, tt.reason, reason)
		})
	}
}

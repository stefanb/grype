package qualifier

import (
	"fmt"

	"github.com/stefanb/grype/grype/pkg/qualifier"
)

type Qualifier interface {
	fmt.Stringer
	Parse() qualifier.Qualifier
}

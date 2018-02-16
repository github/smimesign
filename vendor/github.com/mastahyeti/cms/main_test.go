package cms

import (
	"github.com/mastahyeti/fakeca"
)

var (
	root         = fakeca.New(fakeca.IsCA)
	intermediate = root.Issue(fakeca.IsCA)
	leaf         = intermediate.Issue()
	otherRoot    = fakeca.New(fakeca.IsCA)
)

package log

import (
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

type callInfo struct {
	PC    uintptr
	Path  string
	Line  int
	fcomp []string
}

func newCallInfo(offset int) *callInfo {
	pc, file, line, _ := runtime.Caller(offset)
	return &callInfo{PC: pc, Path: file, Line: line}
}

func (info *callInfo) File() string {
	_, fileName := path.Split(info.Path)
	return fileName
}

func (info *callInfo) components() []string {
	if info.fcomp != nil {
		return info.fcomp
	}

	fname := runtime.FuncForPC(info.PC).Name()
	_, f := path.Split(fname)
	info.fcomp = strings.Split(f, ".")

	return info.fcomp
}

func (info *callInfo) Module() string {
	c := info.components()
	return c[0]
}

func (info *callInfo) receiver(def string) string {
	c := info.components()

	if len(c) < 3 {
		return def
	}

	st := c[1]
	if st[0] == '(' && st[1] == '*' && st[len(st)-1] == ')' {
		return st[2 : len(st)-1]
	}
	return st
}

func (info *callInfo) Struct() string {
	return info.receiver("")
}

func (info *callInfo) Method() string {
	c := info.components()
	if len(c) < 3 {
		return ""
	}
	return c[2]
}

func (info *callInfo) Function() string {
	c := info.components()
	return c[len(c)-1]
}

func (info *callInfo) Namespace() string {
	mod := info.Module()
	return info.receiver(mod)
}

var fmtre = regexp.MustCompile(`\{[[:alpha:]]+\}`)

func (info *callInfo) Format(format string) string {
	return fmtre.ReplaceAllStringFunc(format, func(what string) string {
		switch what {
		case "{Namespace}":
			return info.Namespace()
		case "{File}":
			return info.File()
		case "{Path}":
			return info.Path
		case "{Line}":
			return strconv.Itoa(info.Line)
		case "{Module}":
			return info.Module()
		case "{Struct}":
			return info.Struct()
		case "{Method}":
			return info.Method()
		case "{Function}":
			return info.Function()
		default:
			return what
		}
	})
}

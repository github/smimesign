package config

import (
	"fmt"

	"github.com/github/go/config/env"
)

type loadChain struct {
	chain  []Loader
	byName map[string]Loader
}

func newLoadChain(loaders []Loader) *loadChain {
	byName := make(map[string]Loader)
	for _, loader := range loaders {
		byName[loader.Name()] = loader
	}

	var chain []Loader

	if _, ok := byName["env"]; !ok {
		l := env.New()
		byName["env"] = l
		chain = append(chain, l)
	}
	chain = append(chain, loaders...)

	return &loadChain{
		chain:  chain,
		byName: byName,
	}
}

func (l *loadChain) Lookup(tag *parsedTag) (string, bool, error) {
	if len(tag.Chain) == 0 {
		val, ok, err := l.lookup(tag)
		if err != nil {
			return val, ok, err
		}
		if !ok && tag.Required {
			return val, false, fmt.Errorf("Missing value for required field %q", tag.Field)
		}
		return val, ok, err
	}

	val, ok, err := l.lookupWithChain(tag)
	if err != nil {
		return val, ok, err
	}
	if !ok && tag.Required {
		return val, false, fmt.Errorf("Missing value for required field %q", tag.Field)
	}

	return val, ok, err
}

func (l *loadChain) lookup(tag *parsedTag) (string, bool, error) {
	for _, loader := range l.chain {
		if loader.Explicit() {
			continue
		}

		val, ok, err := loader.Lookup(tag.Field)
		if err != nil {
			return "", false, err
		}
		if ok {
			return val, ok, nil
		}
	}
	return "", false, nil
}

func (l *loadChain) lookupWithChain(tag *parsedTag) (string, bool, error) {
	for _, k := range tag.Chain {
		loader, ok := l.byName[k.Loader]
		if !ok {
			return "", false, fmt.Errorf("Loader %q not provided", k.Loader)
		}

		val, ok, err := loader.Lookup(k.Key)
		if err != nil {
			return "", false, err
		}
		if ok {
			return val, ok, nil
		}
	}
	return "", false, nil
}

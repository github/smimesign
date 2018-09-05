package log

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLevelFromStringGood(t *testing.T) {
	assert.Equal(t, DebugLevel, LevelFromString("debug"))
	assert.Equal(t, DebugLevel, LevelFromString("DEBUG"))
	assert.Equal(t, DebugLevel, LevelFromString("DeBug"))

	assert.Equal(t, InfoLevel, LevelFromString("info"))
	assert.Equal(t, InfoLevel, LevelFromString("INFO"))
	assert.Equal(t, InfoLevel, LevelFromString("INfo"))

	assert.Equal(t, ErrorLevel, LevelFromString("error"))
	assert.Equal(t, ErrorLevel, LevelFromString("ERROR"))
	assert.Equal(t, ErrorLevel, LevelFromString("ErrOr"))

	assert.Equal(t, DisableLogging, LevelFromString("disable"))
	assert.Equal(t, DisableLogging, LevelFromString("DISABLE"))
	assert.Equal(t, DisableLogging, LevelFromString("DiSable"))
}

func TestLevelFromStringBad(t *testing.T) {
	assert.Equal(t, InfoLevel, LevelFromString("unknown"))
	assert.Equal(t, InfoLevel, LevelFromString("warning"))
	assert.Equal(t, InfoLevel, LevelFromString("fatal"))
	assert.Equal(t, InfoLevel, LevelFromString(""))
}

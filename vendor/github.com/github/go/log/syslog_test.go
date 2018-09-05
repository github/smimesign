package log

import (
	"fmt"
	"log/syslog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func ListenSyslog(t *testing.T, socket string, count int) chan []byte {
	reading := make(chan []byte, 8)

	ls, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for i := 0; i < count; i++ {
			buf := make([]byte, 512)
			len, err := ls.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			reading <- buf[:len]
		}
	}()

	return reading
}

func ListenSyslogUDP(t *testing.T, count int) (net.Conn, chan []byte) {
	reading := make(chan []byte, 8)

	ls, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4567})
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for i := 0; i < count; i++ {
			buf := make([]byte, 512)
			len, err := ls.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			reading <- buf[:len]
		}
	}()

	return ls, reading
}

func TestSyslog(t *testing.T) {
	socket := "/tmp/syslogtest-"

	packets := ListenSyslog(t, socket, 6)
	defer os.Remove(socket)

	sys := &Syslog{Facility: syslog.LOG_LOCAL7, Tag: "log-test", Path: socket}
	if err := sys.Connect(); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	nowstr := now.Format(time.Stamp)
	var expected string

	fields1 := []Field{String("key", "val"), Int("int", 42)}
	fields2 := []Field{String("key", "val with word"), Float("float", 33.33)}

	sys.Facility = syslog.LOG_KERN
	sys.Log(nil, ErrorLevel, now, "this is a message", nil, nil)
	assert.Contains(t, string(<-packets), "<3>")

	sys.Facility = syslog.LOG_LOCAL4
	sys.Log(nil, InfoLevel, now, "this is a message", nil, nil)
	assert.Contains(t, string(<-packets), "<166>")

	sys.Facility = syslog.LOG_LOCAL7
	sys.Log(nil, DebugLevel, now, "this is a message", nil, nil)
	expected = fmt.Sprintf("<191>%s log-test[%d]: this is a message\n", nowstr, os.Getpid())
	assert.Equal(t, expected, string(<-packets))

	sys.Log(nil, DebugLevel, now, "another", fields1, nil)
	expected = fmt.Sprintf("<191>%s log-test[%d]: [ key=val int=42 ] another\n", nowstr, os.Getpid())
	assert.Equal(t, expected, string(<-packets))

	sys.Log(nil, DebugLevel, now, "another", fields1, fields1)
	expected = fmt.Sprintf("<191>%s log-test[%d]: [ key=val int=42 key=val int=42 ] another\n", nowstr, os.Getpid())
	assert.Equal(t, expected, string(<-packets))

	sys.Log(nil, DebugLevel, now, "another", fields1, fields2)
	expected = fmt.Sprintf("<191>%s log-test[%d]: [ key=val int=42 key=\"val with word\" float=33.33 ] another\n", nowstr, os.Getpid())
	assert.Equal(t, expected, string(<-packets))
}

func TestSyslogUDP(t *testing.T) {
	ls, packets := ListenSyslogUDP(t, 6)
	defer ls.Close()

	sys := &Syslog{Facility: syslog.LOG_LOCAL7, Tag: "log-test", Proto: "udp", Path: "127.0.0.1:4567"}
	if err := sys.Connect(); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	nowstr := now.Format(time.Stamp)
	var expected string

	fields1 := []Field{String("key", "val"), Int("int", 42)}
	fields2 := []Field{String("key", "val with word"), Float("float", 33.33)}

	sys.Facility = syslog.LOG_KERN
	sys.Log(nil, ErrorLevel, now, "this is a message", nil, nil)
	assert.Contains(t, string(<-packets), "<3>")

	sys.Facility = syslog.LOG_LOCAL4
	sys.Log(nil, InfoLevel, now, "this is a message", nil, nil)
	assert.Contains(t, string(<-packets), "<166>")

	sys.Facility = syslog.LOG_LOCAL7
	sys.Log(nil, DebugLevel, now, "this is a message", nil, nil)
	expected = fmt.Sprintf("<191>%s log-test[%d]: this is a message\n", nowstr, os.Getpid())
	assert.Equal(t, expected, string(<-packets))

	sys.Log(nil, DebugLevel, now, "another", fields1, nil)
	expected = fmt.Sprintf("<191>%s log-test[%d]: [ key=val int=42 ] another\n", nowstr, os.Getpid())
	assert.Equal(t, expected, string(<-packets))

	sys.Log(nil, DebugLevel, now, "another", fields1, fields1)
	expected = fmt.Sprintf("<191>%s log-test[%d]: [ key=val int=42 key=val int=42 ] another\n", nowstr, os.Getpid())
	assert.Equal(t, expected, string(<-packets))

	sys.Log(nil, DebugLevel, now, "another", fields1, fields2)
	expected = fmt.Sprintf("<191>%s log-test[%d]: [ key=val int=42 key=\"val with word\" float=33.33 ] another\n", nowstr, os.Getpid())
	assert.Equal(t, expected, string(<-packets))
}

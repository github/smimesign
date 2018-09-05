package log

import (
	"errors"
	"log/syslog"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// Syslog is a logging formatter that outputs RFC-5424 compatible logging
// entries to the local Syslog daemon
//
// Following the syslog standard, logged entries will have the following format:
//
//	<191>Aug 21 11:20:35 procname[1235]: [ key=val int=42 key=val int=42 ] this is a syslog message
//
// Any formatted data will be stored between square brackets, as specified by the RFC.
type Syslog struct {
	// Facility is the syslog Facility that all log entries will use.
	// See: log/syslog
	Facility syslog.Priority

	// Tag is this process' tag name for the log entries. If empty, defaults
	// to ARGV[0]
	Tag string

	// Proto is the protocol to use for connecting to the syslog daemon. If
	// empty, the default protocol is unixgram.
	Proto string

	// Path is the UNIX datagram socket path for the local syslog daemon. If
	// empty, the default syslog path for the system will be used.
	Path string

	// Timeout is the maximum amount of time the library will block while
	// waiting for the syslog daemon to catch up. If set, the library _will_
	// drop log lines whenever the daemon is busy and cannot receive new
	// packets.
	Timeout time.Duration

	conn net.Conn
	mu   sync.Mutex
}

// Log formats the message for syslog logging.
func (fmt *Syslog) Log(buf []byte, lvl Level, now time.Time, message string, ctx, fields []Field) {
	buf = append(buf, '<')
	buf = fmt.priority(buf, lvl)
	buf = append(buf, '>')
	buf = fmtTimestamp(buf, now)

	buf = append(buf, ' ')
	buf = append(buf, fmt.Tag...)
	buf = append(buf, '[')
	buf = strconv.AppendInt(buf, int64(os.Getpid()), 10)
	buf = append(buf, ']', ':', ' ')

	if len(ctx)+len(fields) > 0 {
		buf = append(buf, '[', ' ')
		for _, f := range ctx {
			buf = fmtField(buf, f)
			buf = append(buf, ' ')
		}
		for _, f := range fields {
			buf = fmtField(buf, f)
			buf = append(buf, ' ')
		}
		buf = append(buf, ']', ' ')
	}

	buf = append(buf, message...)
	buf = append(buf, '\n')
	fmt.write(buf)
}

func (fmt *Syslog) priority(buf []byte, lvl Level) []byte {
	prio := int64(fmt.Facility)

	switch lvl {
	case DebugLevel:
		prio |= int64(syslog.LOG_DEBUG)
	case InfoLevel:
		prio |= int64(syslog.LOG_INFO)
	case ErrorLevel:
		prio |= int64(syslog.LOG_ERR)
	}

	return strconv.AppendInt(buf, prio, 10)
}

func (fmt *Syslog) connect() error {
	var err error

	if fmt.conn != nil {
		fmt.conn.Close()
		fmt.conn = nil
	}

	if fmt.Path != "" {
		fmt.conn, err = dialSyslog(fmt.Proto, fmt.Path)
	} else {
		fmt.conn, err = unixSyslog()
	}

	return err
}

// Connect attemps to connect to the given Unix datagram Path, or
// to the system's default Syslog path, if Path is not set.
//
// Connect returns an error on failure. The Syslog Formatter will
// automatically connect to the Syslog daemon when required, so
// calling Connect is not necessary.
//
// It is however encouraged to do so at program start up time, to
// ensure that the syslog daemon is reachable.
func (fmt *Syslog) Connect() error {
	fmt.mu.Lock()
	defer fmt.mu.Unlock()
	return fmt.connect()
}

func (fmt *Syslog) write(buf []byte) {
	fmt.mu.Lock()
	defer fmt.mu.Unlock()

	if fmt.conn == nil && fmt.connect() != nil {
		return
	}

	if fmt.Timeout != 0 {
		fmt.conn.SetWriteDeadline(time.Now().Add(fmt.Timeout))
	}

	_, err := fmt.conn.Write(buf)
	if err != nil {
		fmt.conn.Close()
		fmt.conn = nil
	}
}

func fmtTimestamp(b []byte, t time.Time) []byte {
	hh, mn, ss := t.Clock()
	_, mm, dd := t.Date()

	b = append(b, mm.String()[:3]...)
	if dd < 10 {
		b = append(b, ' ', ' ', byte('0'+dd))
	} else {
		b = append(b, ' ', byte('0'+dd/10), byte('0'+dd%10))
	}

	return append(b, ' ',
		byte('0'+hh/10), byte('0'+hh%10), ':',
		byte('0'+mn/10), byte('0'+mn%10), ':',
		byte('0'+ss/10), byte('0'+ss%10))
}

func dialSyslog(proto, host string) (net.Conn, error) {
	if proto == "" {
		proto = "unixgram"
	}
	return net.Dial(proto, host)
}

func unixSyslog() (net.Conn, error) {
	logTypes := []string{"unixgram", "unix"}
	logPaths := []string{"/dev/log", "/var/run/syslog", "/var/run/log"}
	for _, network := range logTypes {
		for _, path := range logPaths {
			conn, err := net.Dial(network, path)
			if err != nil {
				continue
			} else {
				return conn, nil
			}
		}
	}
	return nil, errors.New("Unix syslog delivery error")
}

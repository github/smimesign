package sqlperf

import (
	"database/sql"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/github/go/sqlhooks"
	"github.com/github/go/stats"
	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
)

type statlog struct {
	t     stats.Type
	key   string
	value float64
	tags  stats.Tags
}

type fakeStats struct {
	log []*statlog
}

func (n *fakeStats) Start()                                          {}
func (n *fakeStats) Stop()                                           {}
func (n *fakeStats) ReportEvent(title, text string, tags stats.Tags) {}
func (n *fakeStats) Gauge(key string, value int64)                   {}
func (n *fakeStats) Counter(key string, value int64)                 {}
func (n *fakeStats) Histogram(key string, value int64)               {}
func (n *fakeStats) Timing(key string, value time.Duration)          {}
func (n *fakeStats) Event(title, text string)                        {}

func (n *fakeStats) Report(t stats.Type, key string, value float64, tags stats.Tags, rate float32) {
	n.log = append(n.log, &statlog{t, key, value, tags})
}

func driverName() string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	b := make([]byte, 16)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return "mysql-" + string(b)
}

func setupMySQL(t *testing.T, dsn string) {
	db, err := sql.Open("mysql", dsn)
	assert.NoError(t, err)
	assert.NoError(t, db.Ping())
	defer db.Close()

	_, err = db.Exec("CREATE table IF NOT EXISTS users(id int, name text)")
	assert.NoError(t, err)
}

func setupHooks(t *testing.T, stats *fakeStats) (*sql.DB, *sqlperf) {
	dsn := os.Getenv("SQLHOOKS_MYSQL_DSN")
	if dsn == "" {
		t.Skipf("SQLHOOKS_MYSQL_DSN not set")
	}

	setupMySQL(t, dsn)

	hooks := NewHooks(stats)
	name := driverName()
	sql.Register(name, sqlhooks.Wrap(&mysql.MySQLDriver{}, hooks))

	db, err := sql.Open(name, dsn)
	assert.NoError(t, err)
	assert.NoError(t, db.Ping())

	return db, hooks.(*sqlperf)
}

func TestSimpleQuery(t *testing.T) {
	st := &fakeStats{}
	db, _ := setupHooks(t, st)
	defer db.Close()

	rows, err := db.Query("SELECT * FROM users WHERE id = ?", 1)
	assert.NoError(t, err)
	rows.Close()

	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, 1, len(st.log))
	assert.Equal(t, stats.Type('h'), st.log[0].t)
	assert.Equal(t, "sql.query", st.log[0].key)

	tags := string(st.log[0].tags)
	assert.Contains(t, tags, "op:select,")
	assert.Contains(t, tags, "table:users,")
}

func TestCaching(t *testing.T) {
	st := &fakeStats{}
	db, perf := setupHooks(t, st)
	defer db.Close()

	assert.Equal(t, 0, len(perf.cache))

	sql := "SELECT * FROM users WHERE id = ? AND name = ?"
	rows, err := db.Query(sql, int64(1), "Gus")
	assert.NoError(t, err)
	rows.Close()

	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, 1, len(st.log))
	assert.Equal(t, 1, len(perf.cache))

	tags := perf.cache[sql]
	assert.NotNil(t, tags)
	assert.Equal(t, st.log[0].tags, tags)
}

func TestTransaction(t *testing.T) {
	st := &fakeStats{}
	db, _ := setupHooks(t, st)
	defer db.Close()

	tx, err := db.Begin()
	assert.NoError(t, err)

	_, err = tx.Exec("INSERT INTO users (id, name) VALUES(?, ?)", 42, "Jimmy Banana")
	assert.NoError(t, err)

	err = tx.Commit()
	assert.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, 1, len(st.log))
	assert.Contains(t, string(st.log[0].tags), "op:insert,")
}

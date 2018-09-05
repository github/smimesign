package sqlperf

import (
	"context"
	"database/sql/driver"
	"strings"
	"time"

	"github.com/github/go/sqlhooks"
	sqlparser "github.com/github/go/sqlhooks/sqlperf/parser"
	"github.com/github/go/stats"
)

type query struct {
	sql      string
	duration time.Duration
}

type sqlperf struct {
	client stats.Client
	cache  map[string]stats.Tags
	report chan query
}

type sqlperfTime struct{}

func (h *sqlperf) Before(ctx context.Context, sql string, args []driver.NamedValue) (context.Context, error) {
	return context.WithValue(ctx, sqlperfTime{}, time.Now()), nil
}

func (h *sqlperf) After(ctx context.Context, sql string, args []driver.NamedValue) (context.Context, error) {
	begin := ctx.Value(sqlperfTime{}).(time.Time)
	duration := time.Since(begin)
	h.report <- query{sql, duration}
	return ctx, nil
}

func opToString(op int) string {
	switch op {
	case sqlparser.StmtSelect:
		return "select"
	case sqlparser.StmtInsert:
		return "insert"
	case sqlparser.StmtReplace:
		return "replace"
	case sqlparser.StmtUpdate:
		return "update"
	case sqlparser.StmtDelete:
		return "delete"
	case sqlparser.StmtDDL:
		return "ddl"
	case sqlparser.StmtBegin:
		return "begin"
	case sqlparser.StmtCommit:
		return "commit"
	case sqlparser.StmtRollback:
		return "rollback"
	case sqlparser.StmtSet:
		return "set"
	case sqlparser.StmtShow:
		return "show"
	case sqlparser.StmtUse:
		return "use"
	case sqlparser.StmtOther:
		return "other"
	default:
		return "unknown"
	}
}

func (h *sqlperf) queryStats(sql string) stats.Tags {
	info, err := ParseQuery(sql)
	if err != nil {
		return nil
	}

	ts := stats.TagSet{"op": opToString(info.op)}
	if len(info.tables) > 0 {
		ts["table"] = strings.Join(info.tables, ".")
	}

	tags := ts.Tags()
	if len(h.cache) < 1024 {
		h.cache[sql] = tags
	}

	return tags
}

func (h *sqlperf) reporter() {
	for q := range h.report {
		tags := h.cache[q.sql]
		if tags == nil {
			tags = h.queryStats(q.sql)
		}

		t := float64(q.duration) / float64(time.Millisecond)
		h.client.Report(stats.Timing, "sql.query", t, tags, 1.0)
	}
}

func (h *sqlperf) Shutdown() {
	close(h.report)
}

func NewHooks(client stats.Client) sqlhooks.Hooks {
	hooks := &sqlperf{
		client: client,
		cache:  make(map[string]stats.Tags),
		report: make(chan query, 8),
	}
	go hooks.reporter()
	return hooks
}

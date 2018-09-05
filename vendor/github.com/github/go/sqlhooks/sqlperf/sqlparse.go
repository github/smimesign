package sqlperf

import (
	"sort"

	sqlparser "github.com/github/go/sqlhooks/sqlperf/parser"
)

type QueryInfo struct {
	op     int
	tables []string
}

func getOp(ast sqlparser.Statement) string {
	switch ast.(type) {
	case *sqlparser.Select, *sqlparser.Union:
		return "select"
	case *sqlparser.Insert:
		return "insert"
	case *sqlparser.Delete:
		return "delete"
	case *sqlparser.Update:
		return "update"
	default:
		return "other"
	}
}

func handleTableName(names map[string]bool, n sqlparser.TableName) {
	if !n.Name.IsEmpty() && n.Qualifier.IsEmpty() {
		names[n.Name.String()] = true
	}
}

func handleTE(names map[string]bool, te sqlparser.TableExpr) {
	switch ste := te.(type) {
	case *sqlparser.AliasedTableExpr:
		switch n := ste.Expr.(type) {
		case sqlparser.TableName:
			handleTableName(names, n)
		case *sqlparser.Subquery:
			handleStatement(names, n.Select)
		}
	case *sqlparser.ParenTableExpr:
		for _, expr := range ste.Exprs {
			handleTE(names, expr)
		}
	case *sqlparser.JoinTableExpr:
		handleTE(names, ste.LeftExpr)
		handleTE(names, ste.RightExpr)
	}
}

func handleStatement(names map[string]bool, node sqlparser.Statement) {
	sqlparser.Walk(func(node sqlparser.SQLNode) (bool, error) {
		switch te := node.(type) {
		case sqlparser.TableExpr:
			handleTE(names, te)
			return false, nil
		case *sqlparser.Insert:
			handleTableName(names, te.Table)
			return false, nil
		default:
			return true, nil
		}
	}, node)
}

func getTables(sql string) (tables []string, err error) {
	var ast sqlparser.Statement

	ast, err = sqlparser.Parse(sql)
	if err != nil {
		return
	}

	names := make(map[string]bool)
	handleStatement(names, ast)

	for t := range names {
		tables = append(tables, t)
	}
	sort.Strings(tables)
	return
}

func ParseQuery(sql string) (info *QueryInfo, err error) {
	info = &QueryInfo{
		op: sqlparser.Preview(sql),
	}

	switch info.op {
	case sqlparser.StmtSelect,
		sqlparser.StmtInsert,
		sqlparser.StmtReplace,
		sqlparser.StmtUpdate,
		sqlparser.StmtDelete:
		info.tables, err = getTables(sql)
	}

	return
}

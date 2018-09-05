package sqlhooks

import (
	"context"
	"database/sql/driver"
)

// Hook is the hook callback signature
type Hook func(ctx context.Context, query string, args []driver.NamedValue) (context.Context, error)

// Hooks instances may be passed to Wrap() to define an instrumented driver
type Hooks interface {
	Before(ctx context.Context, query string, args []driver.NamedValue) (context.Context, error)
	After(ctx context.Context, query string, args []driver.NamedValue) (context.Context, error)
}

// Driver implements a database/sql/driver.Driver
type Driver struct {
	driver.Driver
	hooks Hooks
}

// Open opens a connection
func (drv *Driver) Open(name string) (driver.Conn, error) {
	conn, err := drv.Driver.Open(name)
	if err != nil {
		return conn, err
	}

	if c, ok := conn.(conn18); ok {
		return &Conn{c, drv.hooks}, nil
	}

	panic("sqlhooks: the given driver does not implement the *Context interfaces")
}

// conn18 is the set of Golang 1.8+ interfaces that a database driver must implement
// in order to be succesfully wrapped by this library.
// Note that the Queryer and Execer interfaces are not really wrapped, but they're
// listed here to work around a bug in the standard library.
// See: https://github.com/golang/go/issues/21663
type conn18 interface {
	driver.Conn
	driver.ConnPrepareContext
	driver.ConnBeginTx

	driver.Queryer
	driver.QueryerContext

	driver.Execer
	driver.ExecerContext
}

// Conn implements a database/sql.driver.Conn
type Conn struct {
	conn18
	hooks Hooks
}

func (conn *Conn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	stmt, err := conn.conn18.PrepareContext(ctx, query)
	if err != nil {
		return stmt, err
	}

	if s, ok := stmt.(stmt18); ok {
		return &Stmt{s, conn.hooks, query}, nil
	}

	panic("sqlhooks: the given driver does not implement the *Context interfaces")
}

func (conn *Conn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	var err error

	// Exec Before Hooks
	if ctx, err = conn.hooks.Before(ctx, query, args); err != nil {
		return nil, err
	}

	rows, err := conn.conn18.QueryContext(ctx, query, args)
	if err != nil {
		return rows, err
	}

	if ctx, err = conn.hooks.After(ctx, query, args); err != nil {
		return nil, err
	}

	return rows, err
}

func (conn *Conn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	var err error

	if ctx, err = conn.hooks.Before(ctx, query, args); err != nil {
		return nil, err
	}

	results, err := conn.conn18.ExecContext(ctx, query, args)
	if err != nil {
		return results, err
	}

	if ctx, err = conn.hooks.After(ctx, query, args); err != nil {
		return nil, err
	}

	return results, err
}

type stmt18 interface {
	driver.Stmt
	driver.StmtExecContext
	driver.StmtQueryContext
}

type Stmt struct {
	stmt18
	hooks Hooks
	query string
}

func (stmt *Stmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	var err error

	// Exec `Before` Hooks
	if ctx, err = stmt.hooks.Before(ctx, stmt.query, args); err != nil {
		return nil, err
	}

	results, err := stmt.stmt18.ExecContext(ctx, args)
	if err != nil {
		return results, err
	}

	if ctx, err = stmt.hooks.After(ctx, stmt.query, args); err != nil {
		return nil, err
	}

	return results, err
}

func (stmt *Stmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	var err error

	// Exec Before Hooks
	if ctx, err = stmt.hooks.Before(ctx, stmt.query, args); err != nil {
		return nil, err
	}

	rows, err := stmt.stmt18.QueryContext(ctx, args)
	if err != nil {
		return rows, err
	}

	if ctx, err = stmt.hooks.After(ctx, stmt.query, args); err != nil {
		return nil, err
	}

	return rows, err
}

// CheckNamedValue implements driver.NamedValueChecker for the wrapped
// statement. We cannot assume all wrapped drivers support this API,
// so our only option is to implement it always, and fallback to
// returning ErrSkip if we cannot find the corresponding interface
// in the wrapped driver. This error return value should force the
// standard library to fall back to the default checker.
func (stmt *Stmt) CheckNamedValue(v *driver.NamedValue) error {
	if nvc, ok := stmt.stmt18.(driver.NamedValueChecker); ok {
		return nvc.CheckNamedValue(v)
	}
	return driver.ErrSkip
}

// ColumnConverter implements the ColumnConverter interface for the
// wrapped statement. Just as with CheckNamedValue, we cannot assume
// this interface is available, so we check for it and otherwise
// return the driver package's default converter.
func (stmt *Stmt) ColumnConverter(idx int) driver.ValueConverter {
	if cc, ok := stmt.stmt18.(driver.ColumnConverter); ok {
		return cc.ColumnConverter(idx)
	}
	return driver.DefaultParameterConverter
}

// Wrap is used to create a new instrumented driver, it takes a vendor specific driver, and a Hooks instance to produce a new driver instance.
// It's usually used inside a sql.Register() statement
func Wrap(driver driver.Driver, hooks Hooks) driver.Driver {
	return &Driver{driver, hooks}
}

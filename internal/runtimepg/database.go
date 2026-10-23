package runtimepg

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Database struct {
	db         *sql.DB
	operations *OperationStore
	bindings   *BindingStore
	deletes    *DeleteCoordinator
}

func Open(ctx context.Context, dsn string) (*Database, error) {
	return open(ctx, dsn, true)
}

// OpenExisting serves a deployment bridge without changing the live schema.
func OpenExisting(ctx context.Context, dsn string) (*Database, error) {
	return open(ctx, dsn, false)
}

func open(ctx context.Context, dsn string, applyMigrations bool) (*Database, error) {
	if ctx == nil || strings.TrimSpace(dsn) == "" {
		return nil, errors.New("PostgreSQL context and DSN are required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(30)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if applyMigrations {
		if err := migrate(ctx, db); err != nil {
			_ = db.Close()
			return nil, err
		}
	} else {
		for _, query := range []string{operationSelect + " LIMIT 0", bindingSelect + " LIMIT 0"} {
			rows, err := db.QueryContext(ctx, query)
			if err != nil {
				_ = db.Close()
				return nil, errors.New("existing runtime schema is incompatible with the API bridge")
			}
			_ = rows.Close()
		}
	}
	database := &Database{db: db}
	database.operations = &OperationStore{db: db}
	database.bindings = &BindingStore{db: db}
	database.deletes = &DeleteCoordinator{db: db}
	return database, nil
}

func (database *Database) Operations() *OperationStore           { return database.operations }
func (database *Database) Bindings() *BindingStore               { return database.bindings }
func (database *Database) DeleteCoordinator() *DeleteCoordinator { return database.deletes }
func (database *Database) Close() error                          { return database.db.Close() }

// CheckReadiness verifies live access to both durable stores with a read-only,
// constant-size query. Empty tables are ready; missing schemas are not.
func (database *Database) CheckReadiness(ctx context.Context) error {
	var hasOperations, hasBindings bool
	return database.db.QueryRowContext(ctx, "SELECT EXISTS ("+operationSelect+"), EXISTS ("+bindingSelect+")").Scan(&hasOperations, &hasBindings)
}

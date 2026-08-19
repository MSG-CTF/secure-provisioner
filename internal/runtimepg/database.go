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
}

func Open(ctx context.Context, dsn string) (*Database, error) {
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
	if err := migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	database := &Database{db: db}
	database.operations = &OperationStore{db: db}
	return database, nil
}

func (database *Database) Operations() *OperationStore { return database.operations }
func (database *Database) Close() error                { return database.db.Close() }

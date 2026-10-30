package runtimepg

import "github.com/MSG-CTF/secure-provisioner/internal/windowsruntime"

func (database *Database) WindowsExecutions() *windowsruntime.PostgresStore {
	return windowsruntime.NewPostgresStore(database.db)
}

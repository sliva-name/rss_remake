package postgres

import (
	"testing"

	"github.com/jackc/pgx/v5"

	"dataguard/internal/connector"
)

func TestDataSourceNameKeepsTheHostApartFromThePort(t *testing.T) {
	for _, host := range []string{"db.internal", "10.20.0.5", "fd00::5"} {
		config, err := pgx.ParseConfig(dataSourceName(connector.Credentials{
			Host: host, Port: 6543, Database: "crm", Username: "dg_scanner", Password: "secret", TLS: connector.TLSDisable,
		}))
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if config.Host != host || config.Port != 6543 {
			t.Errorf("%s: connects to %s port %d", host, config.Host, config.Port)
		}
	}
}

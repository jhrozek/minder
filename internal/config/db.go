//
// Copyright 2023 Stacklok, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/stacklok/mediator/internal/util"
)

// DatabaseConfig is the configuration for the database
type DatabaseConfig struct {
	Host          string `mapstructure:"dbhost"`
	Port          int    `mapstructure:"dbport"`
	User          string `mapstructure:"dbuser"`
	Password      string `mapstructure:"dbpass"`
	Name          string `mapstructure:"dbname"`
	SSLMode       string `mapstructure:"sslmode"`
	EncryptionKey string `mapstructure:"encryption_key"`

	// credential configuration from environment
	credsOnce sync.Once

	// connection string
	connString string
}

// getDBCreds fetches the database credentials from the AWS environment or
// returns the statically-configured password from DatabaseConfig if not in
// a cloud environment.
func (c *DatabaseConfig) getDBCreds(ctx context.Context) string {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		// May not be running on AWS, so skip
		zerolog.Ctx(ctx).Warn().Err(err).Msg("Unable to load AWS config")
		return c.Password
	}
	authToken, err := auth.BuildAuthToken(
		ctx, fmt.Sprintf("%s:%d", c.Host, c.Port), "us-east-1", c.User, cfg.Credentials)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Unable to build auth token")
		return c.Password
	}
	return authToken
}

// GetDBURI returns the database URI
func (c *DatabaseConfig) GetDBURI(ctx context.Context) string {
	c.credsOnce.Do(func() {
		authToken := c.getDBCreds(ctx)

		c.connString = fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
			c.User, authToken, c.Host, c.Port, c.Name, c.SSLMode)
	})

	return c.connString
}

// GetDBConnection returns a connection to the database
func (c *DatabaseConfig) GetDBConnection(ctx context.Context) (*sql.DB, string, error) {
	uri := c.GetDBURI(ctx)
	conn, err := sql.Open("postgres", uri)
	if err != nil {
		return nil, "", err
	}

	// Ensure we actually connected to the database, per Go docs
	if err := conn.Ping(); err != nil {
		//nolint:gosec // Not much we can do about an error here.
		conn.Close()
		return nil, "", err
	}

	zerolog.Ctx(ctx).Info().Msg("Connected to DB")
	return conn, uri, err
}

// RegisterDatabaseFlags registers the flags for the database configuration
func RegisterDatabaseFlags(v *viper.Viper, flags *pflag.FlagSet) error {
	err := util.BindConfigFlagWithShort(
		v, flags, "database.dbhost", "db-host", "H", "localhost", "Database host", flags.StringP)
	if err != nil {
		return err
	}

	err = util.BindConfigFlag(
		v, flags, "database.dbport", "db-port", 5432, "Database port", flags.Int)
	if err != nil {
		return err
	}

	err = util.BindConfigFlagWithShort(
		v, flags, "database.dbuser", "db-user", "u", "postgres", "Database user", flags.StringP)
	if err != nil {
		return err
	}

	err = util.BindConfigFlagWithShort(
		v, flags, "database.dbpass", "db-pass", "P", "postgres", "Database password", flags.StringP)
	if err != nil {
		return err
	}

	err = util.BindConfigFlagWithShort(
		v, flags, "database.dbname", "db-name", "d", "mediator", "Database name", flags.StringP)
	if err != nil {
		return err
	}

	return util.BindConfigFlagWithShort(
		v, flags, "database.sslmode", "db-sslmode", "s", "disable", "Database sslmode", flags.StringP)
}

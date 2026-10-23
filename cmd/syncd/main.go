// Command syncd is the Tabby config sync server and its admin CLI.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"

	"tabbysync/internal/auth"
	"tabbysync/internal/config"
	"tabbysync/internal/configs"
	"tabbysync/internal/crypto"
	"tabbysync/internal/httpapi"
	"tabbysync/internal/store"
)

const usage = `usage: syncd <command> [args]

  serve                                   run the HTTP server
  migrate up|down|status|version          manage the database schema
  user add <name> [-email addr]           add a user (email links the first web login)
  user list|disable|enable [name]         manage users
  token create -user U -name N [-scopes S] [-ttl D]
                                          issue a device token (shown once)
  token import-legacy -user U -name N     import a Tabby Web token from stdin
  token list -user U                      list a user's devices
  token revoke -user U (-id ID | -all)    revoke device tokens
  keys generate -id ID                    print a new keyring line
  keys rewrap                             move all data keys to the primary KEK
  purge                                   delete soft-deleted configs past retention,
                                          expired sessions and idempotency keys
  verify [-database NAME]                 decrypt every revision and check integrity
  health                                  exit 0 if the local server is ready

Configuration is read from TABBYSYNC_* environment variables (see README).
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "serve":
		return serve(ctx, cfg, log)
	case "migrate":
		if err := cfg.RequireDB(); err != nil {
			return err
		}
		if len(rest) != 1 {
			return errors.New("usage: syncd migrate up|down|status|version")
		}
		return store.Migrate(ctx, cfg.DatabaseURL, rest[0])
	case "user":
		return withDB(ctx, cfg, func(db *store.Store) error { return userCmd(ctx, db, rest) })
	case "token":
		return withDB(ctx, cfg, func(db *store.Store) error { return tokenCmd(ctx, db, rest) })
	case "keys":
		return keysCmd(ctx, cfg, log, rest)
	case "purge":
		return withDB(ctx, cfg, func(db *store.Store) error {
			n, err := db.PurgeDeletedConfigs(ctx, time.Now().Add(-cfg.Retention.SoftDelete))
			if err != nil {
				return err
			}
			m, err := db.PurgeExpiredLogins(ctx)
			if err != nil {
				return err
			}
			k, err := db.PurgeExpiredIdempotencyKeys(ctx)
			if err == nil {
				fmt.Printf("purged %d configs, %d expired sessions and login flows, %d idempotency keys\n", n, m, k)
			}
			return err
		})
	case "verify":
		return verifyCmd(ctx, cfg, log, rest)
	case "health":
		return health(cfg)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	}
	return fmt.Errorf("unknown command %q", cmd)
}

func serve(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	if err := errors.Join(cfg.RequireDB(), cfg.RequireKeys()); err != nil {
		return err
	}
	keys, err := crypto.LoadKeyringFile(cfg.KeyringFile, cfg.KEKPrimary)
	if err != nil {
		return err
	}
	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	return httpapi.New(cfg, log, db, newService(cfg, log, db, keys)).Run(ctx)
}

func newService(cfg *config.Config, log *slog.Logger, db *store.Store, keys *crypto.Keyring) *configs.Service {
	return &configs.Service{
		DB:   db,
		Keys: keys,
		Log:  log,
		Limits: configs.Limits{
			MaxConfigBytes:    cfg.Limits.MaxConfigBytes,
			MaxConfigsPerUser: cfg.Limits.MaxConfigsPerUser,
		},
		Retention: store.Retention{
			KeepMin: cfg.Retention.KeepMin,
			MaxAge:  cfg.Retention.MaxAge,
			HardCap: cfg.Retention.HardCap,
		},
	}
}

func withDB(ctx context.Context, cfg *config.Config, fn func(*store.Store) error) error {
	if err := cfg.RequireDB(); err != nil {
		return err
	}
	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	return fn(db)
}

func userCmd(ctx context.Context, db *store.Store, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: syncd user add|list|disable|enable [name]")
	}
	switch args[0] {
	case "list":
		users, err := db.ListUsers(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tUSERNAME\tEMAIL\tWEB LOGIN\tCREATED\tDISABLED")
		for _, u := range users {
			email := "-"
			if u.Email != nil {
				email = *u.Email
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%v\t%s\t%s\n", u.ID, u.Username, email, u.HasIdentity,
				u.CreatedAt.Format(time.DateTime), fmtTime(u.DisabledAt))
		}
		return tw.Flush()
	case "add", "disable", "enable":
		fs := flag.NewFlagSet("user "+args[0], flag.ContinueOnError)
		email := fs.String("email", "", "email for web login: the first OIDC login with this verified email is linked to the user")
		if len(args) < 2 {
			return fmt.Errorf("usage: syncd user %s <name> [-email addr]", args[0])
		}
		name := args[1]
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if args[0] == "add" {
			var em *string
			if *email != "" {
				a, err := mail.ParseAddress(*email)
				if err != nil || a.Address != *email {
					return fmt.Errorf("invalid email %q", *email)
				}
				lower := strings.ToLower(*email)
				em = &lower
			}
			u, err := db.CreateUserWithEmail(ctx, name, em)
			if store.IsUniqueViolation(err) {
				return fmt.Errorf("user %q or email already exists", name)
			}
			if err == nil {
				fmt.Printf("created user %q (id %d)\n", u.Username, u.ID)
			}
			return err
		}
		u, err := db.GetUserByUsername(ctx, name)
		if err != nil {
			return userErr(name, err)
		}
		return db.SetUserDisabled(ctx, u.ID, args[0] == "disable")
	}
	return fmt.Errorf("unknown user command %q", args[0])
}

func tokenCmd(ctx context.Context, db *store.Store, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: syncd token create|import-legacy|list|revoke [flags]")
	}
	fs := flag.NewFlagSet("token "+args[0], flag.ContinueOnError)
	username := fs.String("user", "", "username")
	name := fs.String("name", "", "device name")
	scopes := fs.String("scopes", strings.Join(auth.DefaultScopes, ","), "comma-separated scopes")
	ttl := fs.Duration("ttl", 365*24*time.Hour, "token lifetime, 0 for no expiry")
	id := fs.String("id", "", "device ID")
	all := fs.Bool("all", false, "revoke all of the user's tokens")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *username == "" {
		return errors.New("-user is required")
	}
	u, err := db.GetUserByUsername(ctx, *username)
	if err != nil {
		return userErr(*username, err)
	}

	switch args[0] {
	case "create", "import-legacy":
		if *name == "" {
			return errors.New("-name is required")
		}
		sc, err := auth.ParseScopes(*scopes)
		if err != nil {
			return err
		}
		var token, hint string
		var hash []byte
		if args[0] == "create" {
			if token, hash, hint, err = auth.NewToken(); err != nil {
				return err
			}
		} else {
			// Read from stdin so the token stays out of shell history.
			fmt.Fprintln(os.Stderr, "paste the legacy token and press Enter:")
			line, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil && line == "" {
				return err
			}
			legacy := strings.TrimSpace(line)
			if !auth.ValidTokenSyntax(legacy) {
				return errors.New("that does not look like a token")
			}
			hash, hint = auth.HashToken(legacy), auth.Hint(legacy)
		}
		d := store.Device{ID: uuid.New(), UserID: u.ID, Name: *name, TokenHint: hint, Scopes: sc}
		if *ttl > 0 {
			exp := time.Now().Add(*ttl)
			d.ExpiresAt = &exp
		}
		d, err = db.CreateDevice(ctx, d, hash)
		if store.IsUniqueViolation(err) {
			return errors.New("this token is already registered")
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "device %s created for %q, scopes %s, expires %s\n",
			d.ID, u.Username, strings.Join(d.Scopes, ","), fmtTime(d.ExpiresAt))
		if token != "" {
			fmt.Fprintln(os.Stderr, "token (shown only once):")
			fmt.Println(token)
		}
		return nil
	case "list":
		devs, err := db.ListDevices(ctx, u.ID)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tTOKEN\tSCOPES\tLAST USED\tEXPIRES\tREVOKED")
		for _, d := range devs {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", d.ID, d.Name, d.TokenHint,
				strings.Join(d.Scopes, ","), fmtTime(d.LastUsedAt), fmtTime(d.ExpiresAt), fmtTime(d.RevokedAt))
		}
		return tw.Flush()
	case "revoke":
		if *all {
			n, err := db.RevokeAllDevices(ctx, u.ID)
			if err == nil {
				fmt.Printf("revoked %d tokens\n", n)
			}
			return err
		}
		devID, err := uuid.Parse(*id)
		if err != nil {
			return errors.New("-id must be a device ID (see token list) or use -all")
		}
		if err := db.RevokeDevice(ctx, u.ID, devID); errors.Is(err, store.ErrNotFound) {
			return errors.New("no such device for this user")
		} else if err != nil {
			return err
		}
		fmt.Println("revoked")
		return nil
	}
	return fmt.Errorf("unknown token command %q", args[0])
}

func keysCmd(ctx context.Context, cfg *config.Config, log *slog.Logger, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: syncd keys generate -id ID | keys rewrap")
	}
	switch args[0] {
	case "generate":
		fs := flag.NewFlagSet("keys generate", flag.ContinueOnError)
		id := fs.String("id", "", "key ID, e.g. k2026-10")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		line, err := crypto.GenerateKeyLine(*id)
		if err == nil {
			fmt.Println(line)
		}
		return err
	case "rewrap":
		if err := cfg.RequireKeys(); err != nil {
			return err
		}
		keys, err := crypto.LoadKeyringFile(cfg.KeyringFile, cfg.KEKPrimary)
		if err != nil {
			return err
		}
		return withDB(ctx, cfg, func(db *store.Store) error {
			n, err := newService(cfg, log, db, keys).RewrapAll(ctx)
			fmt.Printf("rewrapped %d revisions to %s\n", n, keys.PrimaryID())
			return err
		})
	}
	return fmt.Errorf("unknown keys command %q", args[0])
}

func userErr(name string, err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no user %q", name)
	}
	return err
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Local().Format(time.DateTime)
}

// verifyCmd checks that every revision decrypts. With -database it reads
// another database on the same server, e.g. a restored backup.
func verifyCmd(ctx context.Context, cfg *config.Config, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	dbName := fs.String("database", "", "database name to check instead of the configured one")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := errors.Join(cfg.RequireDB(), cfg.RequireKeys()); err != nil {
		return err
	}
	if *dbName != "" {
		u, err := url.Parse(cfg.DatabaseURL)
		if err != nil || u.Scheme == "" {
			return errors.New("-database needs TABBYSYNC_DATABASE_URL in URL form")
		}
		u.Path = "/" + *dbName
		cfg.DatabaseURL = u.String()
	}
	keys, err := crypto.LoadKeyringFile(cfg.KeyringFile, cfg.KEKPrimary)
	if err != nil {
		return err
	}
	return withDB(ctx, cfg, func(db *store.Store) error {
		rep, err := newService(cfg, log, db, keys).Verify(ctx)
		if err != nil {
			return err
		}
		for _, p := range rep.Problems {
			fmt.Println("PROBLEM:", p)
		}
		fmt.Printf("verified %d revisions, %d problems\n", rep.Revisions, len(rep.Problems))
		if len(rep.Problems) > 0 {
			return errors.New("integrity check failed")
		}
		return nil
	})
}

// health is the container health check: the image has no shell or curl.
func health(cfg *config.Config) error {
	host, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	scheme := "http"
	client := &http.Client{Timeout: 3 * time.Second}
	if cfg.TLSCertFile != "" {
		scheme = "https"
		client.Transport = &http.Transport{
			// The certificate is for the public name, not the loopback address.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // loopback only
		}
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		scheme+"://"+net.JoinHostPort(host, port)+"/readyz", nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close() //nolint:errcheck // nothing to do
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("not ready: %s", res.Status)
	}
	return nil
}

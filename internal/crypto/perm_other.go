//go:build !unix

package crypto

import "os"

// Windows ACLs are not mapped onto Unix permission bits; nothing to check.
func checkPermissions(*os.File) error { return nil }

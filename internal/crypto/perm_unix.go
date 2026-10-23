//go:build unix

package crypto

import (
	"fmt"
	"os"
)

// checkPermissions refuses a keyring readable or writable by group or others.
func checkPermissions(f *os.File) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("keyring %s: permissions %v are too open, use 0400 or 0600", f.Name(), st.Mode().Perm())
	}
	return nil
}

//go:build !windows

package tpmlog

import (
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// openTPM 은 리소스 매니저 장치를 먼저 시도하고, 없으면 원시 장치를 연다.
func openTPM() (transport.TPMCloser, error) {
	var lastErr error
	for _, path := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		if _, err := os.Stat(path); err != nil {
			lastErr = err
			continue
		}
		tpm, err := linuxtpm.Open(path)
		if err == nil {
			return tpm, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("no TPM device available: %w", lastErr)
}

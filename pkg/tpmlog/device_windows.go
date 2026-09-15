//go:build windows

package tpmlog

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

// openTPM 은 TBS(tbs.dll)를 통해 로컬 TPM 을 연다.
func openTPM() (transport.TPMCloser, error) { return windowstpm.Open() }

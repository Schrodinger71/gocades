//go:build linux
// +build linux

package main

/*
#cgo CFLAGS: -DUNIX -I/opt/cprocsp/include/pki -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include
#cgo LDFLAGS: -L/opt/cprocsp/lib/amd64 -lcades -lcapi20 -lcapi10 -lrdrsup
#include <cades.h>
#include <stdlib.h>
#include "signer.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

type Signer struct {
}

func NewSigner() *Signer {
	return &Signer{}
}

func (s *Signer) Sign(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("data cannot be empty")
	}

	var (
		outSig *C.uchar
		outLen C.int
	)

	result := C.cades_sign_simple(
		(*C.char)(unsafe.Pointer(&data[0])),
		C.int(len(data)),
		&outSig,
		&outLen,
	)

	if result != 0 {
		return nil, s.mapError(result)
	}

	// Ensure C memory is freed
	signature := C.GoBytes(unsafe.Pointer(outSig), outLen)
	C.free(unsafe.Pointer(outSig))

	return signature, nil
}

func (s *Signer) mapError(code C.int) error {
	switch code {
	case -1:
		return errors.New("invalid input parameters")
	case -2:
		return errors.New("failed to open certificate store")
	case -3:
		return errors.New("no valid certificate with private key found")
	case -4, -5, -6:
		return fmt.Errorf("signing operation failed (code %d)", code)
	default:
		return fmt.Errorf("unknown error (code %d)", code)
	}
}

func main() {
	signer := NewSigner()
	data := []byte("Hello, World!")

	signature, err := signer.Sign(data)
	if err != nil {
		fmt.Printf("Signing failed: %v\n", err)
		return
	}

	fmt.Printf("Signature created successfully: %d bytes\n", len(signature))
}

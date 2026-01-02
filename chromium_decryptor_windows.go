//go:build windows

package sweetcookie

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var chromiumDPAPIPrefix = [...]byte{
	1, 0, 0, 0, 208, 140, 157, 223, 1, 21, 209, 17, 140, 122, 0, 192, 79, 194, 151, 235,
} // 0x01000000D08C9DDF0115D1118C7A00C04FC297EB

func chromiumDecryptor(vendor chromiumVendor, stores []chromiumStore, _ time.Duration) (chromiumDecryptFunc, []string) {
	userDataDir := ""
	for _, st := range stores {
		if st.userData != "" {
			userDataDir = st.userData
			break
		}
	}
	if userDataDir == "" {
		return nil, []string{fmt.Sprintf("sweetcookie: %s Local State path unavailable", vendor.label)}
	}

	key, err := chromiumWindowsMasterKey(userDataDir)
	if err != nil {
		return nil, []string{fmt.Sprintf("sweetcookie: %s master key read failed: %v", vendor.label, err)}
	}

	var warnedV20 sync.Once
	return func(encrypted []byte, metaVersion int64) ([]byte, bool) {
		if len(encrypted) < 3 {
			return nil, false
		}

		if bytes.HasPrefix(encrypted, chromiumDPAPIPrefix[:]) {
			plain, err := dpapiUnprotect(encrypted)
			if err != nil {
				return nil, false
			}
			plain = chromiumStripHashPrefix(plain, metaVersion)
			return plain, true
		}

		if len(encrypted) >= 3 && string(encrypted[:3]) == "v20" {
			warnedV20.Do(func() {})
			return nil, false
		}

		plain, err := chromiumDecryptAES256GCM(encrypted, key, metaVersion)
		if err != nil {
			return nil, false
		}
		return plain, true
	}, nil
}

func chromiumWindowsMasterKey(userDataDir string) ([]byte, error) {
	statePath := filepath.Join(userDataDir, "Local State")
	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		return nil, err
	}

	var localState struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(stateBytes, &localState); err != nil {
		return nil, err
	}
	encB64 := strings.TrimSpace(localState.OSCrypt.EncryptedKey)
	if encB64 == "" {
		return nil, errors.New("local state missing os_crypt.encrypted_key")
	}
	enc, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(enc, []byte("DPAPI")) {
		return nil, errors.New("encrypted_key missing DPAPI prefix")
	}
	enc = enc[len("DPAPI"):]
	key, err := dpapiUnprotect(enc)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("master key not 32 bytes (got %d)", len(key))
	}
	return key, nil
}

func dpapiUnprotect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty dpapi input")
	}

	var outBlob dataBlob
	if err := cryptUnprotectData(newBlob(data), &outBlob); err != nil {
		return nil, err
	}
	defer func() {
		_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.pbData))) //nolint:gosec // Windows API requires this.
	}()
	return outBlob.bytes(), nil
}

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(d []byte) *dataBlob {
	if len(d) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{pbData: &d[0], cbData: uint32(len(d))}
}

func (b *dataBlob) bytes() []byte {
	if b == nil || b.cbData == 0 || b.pbData == nil {
		return nil
	}
	out := make([]byte, b.cbData)
	copy(out, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:b.cbData:b.cbData])
	return out
}

func cryptUnprotectData(in *dataBlob, out *dataBlob) error {
	// windows.CryptUnprotectData wrapper in x/sys is awkward for raw blobs; call proc directly.
	dll := windows.NewLazySystemDLL("Crypt32.dll")
	proc := dll.NewProc("CryptUnprotectData")
	const cryptprotectUIForbidden = 0x1
	r, _, e := proc.Call(
		uintptr(unsafe.Pointer(in)),
		0,
		0,
		0,
		0,
		cryptprotectUIForbidden,
		uintptr(unsafe.Pointer(out)),
	)
	if r == 0 {
		return e
	}
	return nil
}

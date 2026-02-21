package isolated

import (
	"bytes"
	"io"
	"net/http"
	"os"
)

//ctguard:isolated
//ctguard:secret key
func sendKeyOverHTTP(key []byte) {
	body := bytes.NewReader(key)
	_, _ = http.Post("http://example.com", "application/octet-stream", body) // want "CT007"
}

//ctguard:isolated
//ctguard:secret secret
func writeSecretToFile(secret []byte) {
	_ = os.WriteFile("/tmp/out", secret, 0o600) // want "CT007"
}

//ctguard:secret token
func blockIsolatedNetwork(token []byte) {
	//ctguard:isolated begin
	_, _ = http.Post("http://example.com", "application/octet-stream", bytes.NewReader(token)) // want "CT007"
	//ctguard:isolated end
}

//ctguard:secret data
func blockIsolatedFile(data []byte) {
	//ctguard:isolated begin
	_ = os.WriteFile("/tmp/out", data, 0o600) // want "CT007"
	//ctguard:isolated end
}

//ctguard:secret secret
func notIsolatedNetwork(secret []byte) {
	_, _ = http.Post("http://example.com", "application/octet-stream", bytes.NewReader(secret))
}

//ctguard:isolated
func isolatedNoTaint(data []byte) {
	_ = os.WriteFile("/tmp/out", data, 0o600)
}

//ctguard:isolated
//ctguard:secret name
func createFileWithSecretName(name string) {
	_, _ = os.Create(name) // want "CT007"
}

//ctguard:isolated
//ctguard:secret payload
func writeToWriter(w io.Writer, payload []byte) {
	_, _ = w.Write(payload) // want "CT007"
}

//ctguard:secret secret
func ioOutsideBlock(secret []byte) {
	_ = os.WriteFile("/tmp/before", secret, 0o600)

	//ctguard:isolated begin
	_ = len(secret)
	//ctguard:isolated end

	_ = os.WriteFile("/tmp/after", secret, 0o600)
}

//ctguard:isolated
//ctguard:secret src
func copySecret(dst io.Writer, src io.Reader) {
	_, _ = io.Copy(dst, src) // want "CT007"
}

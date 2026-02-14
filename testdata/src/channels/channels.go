package channels

// CT006: Channel operations with secret data tests

//ctguard:secret secret
func sendToChannel(ch chan string, secret string) {
	ch <- secret // want "CT006"
}

//ctguard:secret password
func sendPasswordToChannel(ch chan string, password string) {
	ch <- password // want "CT006"
}

//ctguard:secret key
func receiveFromChannel(ch chan string, key string) {
	ch <- key // want "CT006"
	_ = <-ch  // want "CT006"
}

//ctguard:secret token
func receiveFromTaintedChannel(ch chan string, token string) {
	ch <- token // want "CT006"
	val := <-ch // want "CT006"
	_ = val
}

// Safe: sending public data to channel
func sendPublicToChannel(ch chan string, public string) {
	ch <- public
}

// Safe: receiving from non-tainted channel
func receiveFromCleanChannel(ch chan string) {
	_ = <-ch
}

//ctguard:secret secret
func mixedOperations(ch chan string, secret string, public string) {
	ch <- public
	ch <- secret // want "CT006"
	_ = <-ch     // want "CT006"
}

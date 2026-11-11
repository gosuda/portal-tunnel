package localtls

type fileSource struct{ certFile, keyFile, hostname string }

func (s *fileSource) acquire() (*pinnedChain, error) {
	return loadLocalPin(s.certFile, s.keyFile, s.hostname)
}

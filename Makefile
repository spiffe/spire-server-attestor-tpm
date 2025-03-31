all: bin/spire-server-attestor-tpm-signer-http bin/spire-server-attestor-tpm-signer-unix bin/spire-server-attestor-tpm-sign bin/spire-server-attestor-tpm-verifier

bin/spire-server-attestor-tpm-signer-http: cmd/spire-server-attestor-tpm-signer-http/main.go
	mkdir -p bin
	go build -o bin/spire-server-attestor-tpm-signer-http cmd/spire-server-attestor-tpm-signer-http/main.go

bin/spire-server-attestor-tpm-signer-unix: cmd/spire-server-attestor-tpm-signer-unix/main.go
	mkdir -p bin
	go build -o bin/spire-server-attestor-tpm-signer-unix cmd/spire-server-attestor-tpm-signer-unix/main.go

bin/spire-server-attestor-tpm-sign: cmd/spire-server-attestor-tpm-sign/main.go
	mkdir -p bin
	go build -o bin/spire-server-attestor-tpm-sign cmd/spire-server-attestor-tpm-sign/main.go

bin/spire-server-attestor-tpm-verifier: cmd/spire-server-attestor-tpm-verifier/main.go
	mkdir -p bin
	go build -o bin/spire-server-attestor-tpm-verifier cmd/spire-server-attestor-tpm-verifier/main.go

install: all
	mkdir -p $(DESTDIR)/usr/lib/systemd/system
	mkdir -p $(DESTDIR)/etc/spire/server-attestor-tpm/keys
	mkdir -p $(DESTDIR)/var/run/spire/server-attestor-tpm
	install conf/signer-http.conf $(DESTDIR)/etc/spire/server-attestor-tpm
	install conf/signer-unix.conf $(DESTDIR)/etc/spire/server-attestor-tpm
	install conf/verifier.conf $(DESTDIR)/etc/spire/server-attestor-tpm
	install bin/spire-server-attestor-tpm-sign $(DESTDIR)/usr/bin
	install bin/spire-server-attestor-tpm-signer-unix $(DESTDIR)/usr/bin
	install bin/spire-server-attestor-tpm-signer-http $(DESTDIR)/usr/bin
	install bin/spire-server-attestor-tpm-verifier $(DESTDIR)/usr/bin
	install systemd/spire-server-attestor-tpm-signer-http.service $(DESTDIR)/usr/lib/systemd/system
	install systemd/spire-server-attestor-tpm-signer-unix.service $(DESTDIR)/usr/lib/systemd/system
	install systemd/spire-server-attestor-tpm-verifier.service $(DESTDIR)/usr/lib/systemd/system

clean:
	rm -f bin/spire-server-attestor-tpm-signer-http bin/spire-server-attestor-tpm-signer-unix bin/spire-server-attestor-tpm-sign bin/spire-server-attestor-tpm-verifier

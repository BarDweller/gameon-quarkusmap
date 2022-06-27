# Gameon Quarkus Map

![Publish](https://github.com/bardweller/gameon-quarkusmap/actions/workflows/main.yml/badge.svg)
![ReleaseDate](https://img.shields.io/github/release-date/bardweller/gameon-quarkusmap)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/bardweller/gameon-quarkusmap?display_name=release)
![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/bardweller/gameon-quarkusmap)

A recreation of the GameOn Map service using Quarkus, rather than JEE.

# Build instructions. 

`git clone https://github.com/BarDweller/gameon-quarkusmap.git`

If you have graalvm etc locally.. then
`./mvnw clean package -Dnative`

If you don't, and you have Docker (or podman), you can use.. 
`./mvnw clean package -Dnative -Dquarkus.native.container-build=true`

Finally build the container using 
`docker build -t gameontext/quarkus-map:1.0 -f src/main/docker/Dockerfile.native .`

(or, if using RancherDesktop for testing.. )
`nerdctl build --namespace k8s.io -t gameontext/quarkus-map:1.0 -f src/main/docker/Dockerfile.native .`
(if testing locally with gameon running in kube remotely, 
you can use `kubectl port-forward service/couchdb 5984:5984 -n gameon-system` and a `COUCHDB_URL` of `http://localhost:5984`
retrieve the COUCHDB_USER & COUCHDB_PASSWORD from the gameon global-config ConfigMap in the gameon-system namespace )

# Config

This app requires the following env vars to be set. 

| Env var | Purpose |
|---------|---------|
|JWT_PUBLIC_CERT| The pem certificate to trust as a multiline env var (eg, `----BEGIN CERTIFICATE---` etc.. etc etc) |
|JWT_PRIVATE_KEY| The private key for the JWT_PUBLIC_CERT as a multiline env var (eg, `-----BEGIN PRIVATE KEY-----` etc.. etc etc) used to re-sign tokens to invoke player service|
|COUCHDB_USER| userid to talk to couchdb |
|COUCHDB_PASSWORD| password to talk to couchdb |
|COUCHDB_SERVICE_URL|url to talk to couchdb|
|SYSTEM_ID|the id to allow access to sensitive data with (probably `dummy:dummy.AnonymousUser` if testing locally), also used to access player service|
|PLAYER_SERVICE_URL|url to talk to gameon player service|
|MAP_KEY|the key used by this service, when talking to player service|
|SWEEP_ID|the id used by sweep when accessing this service|
|SWEEP_SECRET|the secret used by sweep when accessing this service|







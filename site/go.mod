// The site is its own module, not a package of the vault server: it deploys on
// its own schedule and depends on github.com/hammondus/mailer, which the vault
// server must never pull in. Nesting a go.mod here removes site/ from the
// parent module automatically.
module github.com/hammondus/ownvault/site

go 1.26.5

require (
	github.com/hammondus/mailer v0.1.1
	github.com/hammondus/nitrokit v0.1.1
)

require (
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)

build:
	goreleaser --snapshot --rm-dist

run:
	./dist/aws-sso-fetcher_darwin_amd64/aws-sso-fetcher hpydev_dev

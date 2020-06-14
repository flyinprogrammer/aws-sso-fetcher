# AWS SSO Fetcher

# Depreciation Notice

Please stop using this tool and start using [aws-vault](https://github.com/99designs/aws-vault) instead.

[v6.0.0-beta5](https://github.com/99designs/aws-vault/releases/tag/v6.0.0-beta5)

Has support for SSO via [PR-594](https://github.com/99designs/aws-vault/pull/549)

`aws-vault` has a community and is leading from the front in terms of keeping your
credentials secure. We should all go support them.

---

Right now, most AWS SDKs don't support the new SSO credential
provider that the AWS CLI v2 supports.

While the SDKs are catching up to support SSO credentials in their
default credential providers, we can use this tool as a credential
process to fetch credentials because most SDKs already support the
`credential_process` [directive](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html).

## Example Usage:

Inside your `~/.aws/config` you'll set something like this up:

```ini
[profile acme_dev]
sso_start_url = https://acme.awsapps.com/start/
sso_region = us-east-2
sso_account_id = 0123456789
sso_role_name = AWSAdministratorAccess
region = us-east-2
output = json
credential_process = /Users/alice/bin/aws-sso-fetcher acme_dev
```

Once you get SSO credentials with:

```bash
aws sso login --profile=acme_dev
```

You can then start using all kinds of software with the profile:

```bash
export AWS_PROFILE=acme_dev
aws ec2 describe-vpcs
```

But of course you didn't download this tool to use it with the
AWS CLI, you downloaded it so that you could launch other applications
using `AWS_PROFILE` without wrapper scripts.

It's also been reported that you might need to also set:

```bash
export AWS_SDK_LOAD_CONFIG=1
```

to get Golang applications (i.e. `terraform`) to correctly use the the `config` file.

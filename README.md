# AWS SSO Fetcher

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

[profile wrap_acme_dev]
credential_process = "/Users/alice/bin/aws-sso-fetcher" "acme_dev"
region = us-west-1
output = json

```

Once you get SSO credentials with:

```bash
export AWS_PROFILE=acme_dev
aws sso login
```

You can then start using software with the other wrap profile:

```bash
export AWS_PROFILE=wrap_acme_dev
aws ec2 describe-vpcs
```

But of course you didn't download this tool to use it with the
AWS CLI, you used it so that you could launch other applications
using `AWS_PROFILE` or wrapper scripts.

# AWS Amplify, Cognito user pools and AppSync

Ownership first: **Cognito identity pools** (`GetId`,
`GetCredentialsForIdentity`, the unauthenticated IAM role) are `cloud-iam-deep`.
This file covers what sits next to them in the same Amplify config: the
**user pool** (sign-up, attributes, user existence errors) and **AppSync**
(GraphQL with API-key auth). GraphQL technique itself is `hunt-graphql`.

## Config files

| File | Generation | Fields that matter |
|---|---|---|
| `aws-exports.js` / `amplifyconfiguration.json` | Amplify Gen 1 | `aws_project_region`, `aws_user_pools_id`, `aws_user_pools_web_client_id`, `aws_cognito_identity_pool_id`, `aws_appsync_graphqlEndpoint`, `aws_appsync_region`, `aws_appsync_authenticationType`, `aws_appsync_apiKey`, `oauth.domain` |
| `amplify_outputs.json` | Amplify Gen 2 | `auth.user_pool_id`, `auth.user_pool_client_id`, `auth.identity_pool_id`, `auth.aws_region`; `data.url`, `data.api_key`, `data.default_authorization_type` (`API_KEY`, `AMAZON_COGNITO_USER_POOLS`, `AWS_IAM`, `OPENID_CONNECT`), `data.authorization_types` |
| `awsconfiguration.json` | Mobile SDKs | `CognitoUserPool.Default.PoolId` / `AppClientId`, `AppSync.Default.ApiUrl` / `ApiKey` / `AuthMode` |

All of these are public identifiers; AWS's own answers describe them as such.
An app client **secret** in the client config is a mistake (low on its own:
it is not a privilege, only an extra parameter, but it signals copy-pasted
server config).

## Cognito user pool: Stage A

```bash
POOL='<region>_<id>'; R='<region>'
# OIDC discovery and keys for the pool (public by design).
curl -s "https://cognito-idp.$R.amazonaws.com/$POOL/.well-known/openid-configuration" | head -c 800
```

**Self-registration.** With `AllowAdminCreateUserOnly` true, `SignUp` fails
with `NotAuthorizedException` and managed login hides the sign-up link (AWS
"Configuring policies for user creation"). Read-only signal: load the managed
login page for the app's own client and look for the link:

```
https://<domain>.auth.<region>.amazoncognito.com/login?client_id=<client-id>&response_type=code&redirect_uri=<registered-redirect>
```

The link's absence does not prove sign-up is off: hiding the UI does not
disable the `SignUp` API, which only needs the client ID. The only definitive
test is a `SignUp` call: Stage B below.

**User existence errors.** `PreventUserExistenceErrors` defaults to `LEGACY`
(disabled) for app clients created through the API and `ENABLED` for clients
created in the console (AWS "Managing user existence error responses"). Under
`LEGACY`, sign-in with an unknown username returns `UserNotFoundException`.
Testing it is an authentication attempt: Stage B, one random username, and it
is Low on its own.

## Cognito user pool: what the findings are

| Misconfiguration | Why it matters | How it is proven |
|---|---|---|
| Self-registration open on an internal or B2B app | Anyone becomes an authenticated user; every "authenticated" permission in AppSync, API Gateway authorizers and the identity pool's authenticated role opens up | Stage B `SignUp` on your own address |
| App client allows writing a custom attribute used for authorization (`custom:role`, `custom:tenant`, `custom:isAdmin`) | `UpdateUserAttributes` with your own access token changes your claims; the app trusts the ID token's `custom:` claims | Stage B on your own account; read the token before and after |
| Email or phone change becomes active before verification | AWS: without "Keep original attribute value active when an update is pending" (`AttributesRequireVerificationBeforeUpdate`), the original value stops working and the new value is unverified but set. Apps that key identity on `email` rather than `sub` can be confused | Stage B on your own account, never another user's |
| Identity pool ID present | IAM credentials for anonymous or self-registered users | `cloud-iam-deep` |

Real cases:

- **CVE-2026-6912** (AWS Ops Wheel, Apr 2026): the user pool client had no
  `WriteAttributes` restriction, so any authenticated user could set
  `custom:deployment_admin` through `UpdateUserAttributes` and become
  deployment admin. <https://github.com/aws/aws-ops-wheel/security/advisories/GHSA-qvfh-9cjw-8wwq>,
  AWS bulletin 2026-018.
- **CVE-2024-28056** (Amplify CLI before 12.10.1): removing the Auth category
  left IAM role trust policies that allowed `sts:AssumeRoleWithWebIdentity`
  with no condition, so the roles were assumable from any Cognito identity pool.
  Datadog Security Labs research; AWS fixed the CLI (Jan 2024) and added an STS
  mitigation. <https://aws.amazon.com/security/security-bulletins/AWS-2024-003>,
  <https://securitylabs.datadoghq.com/articles/amplified-exposure-how-aws-flaws-made-amplify-iam-roles-vulnerable-to-takeover/>.
  The IAM side is `cloud-iam-deep`.
- **CVE-2023-22893** (Strapi users-permissions 3.2.1-4.5.x): the AWS Cognito
  login provider did not verify the ID token, so a forged `alg: none` token
  impersonated any user. An app-side Cognito integration bug: see
  `self-hosted-baas.md`.

## AppSync

```bash
EP='<appsync-graphql-endpoint>'; KEY='<API_KEY_FROM_CONFIG>'
# (read) Does the key work at all?
curl -s "$EP" -H "x-api-key: $KEY" -H 'Content-Type: application/json' -d '{"query":"{__typename}"}'
```

- Keys look like `da2-...`. The current key version accepts an expiry from 1 to
  365 days; the CDK default is 7 days (AWS CDK `ApiKeyConfig`). A key in a
  production bundle is often long-lived on purpose.
- Introspection: AWS added a per-API switch on 19 Dec 2023; if unset it is
  `ENABLED`. Disabled introspection returns a validation error; `hunt-graphql`
  covers field suggestion and wordlist fallbacks.
- `API_KEY` as the **default** mode means every operation without an
  `@auth` override is open to holders of the key. That is the finding when a
  query returns user data. Use the smallest list the schema offers (`limit: 1`)
  and select only identifiers.
- Mutations are Stage B. Subscriptions over WebSocket are reads but stream
  other users' events in real time; keep them to a few seconds, Stage A only on
  explicit operator approval.
- Multi-auth APIs: a type annotated for `iam` or `userPools` but reachable with
  the API key, or `public` rules on a model holding personal data (Amplify's
  `allow.publicApiKey()` in Gen 2, `{ allow: public }` in Gen 1), are the usual
  root causes.

## Stage B on Cognito and AppSync

All of these need the SKILL.md Step 4 sign-off naming the pool, client and
address.

```bash
# Stage B: written sign-off required. One SignUp, your own address; it creates an UNCONFIRMED user and may send a code.
aws cognito-idp sign-up --region <region> --no-sign-request \
  --client-id <client-id> --username tester+hcb@yourdomain.example \
  --password '<policy-compliant-password>' \
  --user-attributes Name=email,Value=tester+hcb@yourdomain.example
```

`NotAuthorizedException` ("SignUp is not permitted for this user pool" is the
commonly seen message, verify) = self-registration off. `UsernameExistsException`
= you already registered. Success = open; list the user for the client to
delete. A deliberately invalid password may return `InvalidPasswordException`
without creating anything, but whether the admin-only check runs first is
undocumented (verify): treat that probe as Stage B as well.

```bash
# Stage B: written sign-off required. Own account only. Read your attributes, try one custom attribute, read again.
aws cognito-idp get-user --region <region> --access-token "$ACCESS_TOKEN"
aws cognito-idp update-user-attributes --region <region> --access-token "$ACCESS_TOKEN" \
  --user-attributes Name=custom:<attr>,Value=<value-the-app-checks>
```

A `NotAuthorizedException` naming the attribute means the client blocks it,
which is the correct state.

## Sources (checked October 2026)

- User creation policy: <https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-admin-create-user-policy.html>
- User existence errors: <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-managing-errors.html>
- Attribute verification on update: <https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-email-phone-verification.html>
- Managed login endpoints: <https://docs.aws.amazon.com/cognito/latest/developerguide/managed-login-endpoints.html>
- AppSync introspection control: <https://aws.amazon.com/about-aws/whats-new/2023/12/aws-appsync-additional-configurations-manage-graphql-api-usage>
- AppSync API key lifetime: <https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_appsync.ApiKeyConfig.html>
- Amplify outputs: <https://docs.amplify.aws/vue/reference/amplify_outputs/>

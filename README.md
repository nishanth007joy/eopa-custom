# EOPA

[![OPA v1.8.0](https://openpolicyagent.org/badge/v1.8.0)](https://github.com/open-policy-agent/opa/releases/tag/v1.8.0)
[![Regal v0.35.1](https://img.shields.io/github/v/release/open-policy-agent/regal?filter=v0.35.1&label=Regal)](https://github.com/open-policy-agent/regal/releases/tag/v0.35.1)

A version of OPA designed for data heavy workloads, with data-filtering functionality included.

## New!

**EOPA has been donated to the OPA community**, and we invite you to take a look around.

- Try EOPA if you have to integrate with databases including DynamoDB, Postgres, and Neo4j. See the full list [here](./docs/eopa/_eopa-introduction.md)
- Experiment with EOPA's performance improvements and share feedback in `#help` on [Slack](https://slack.openpolicyagent.org/)
- See the [A Note from Teemu, Tim and Torin](https://blog.openpolicyagent.org/note-from-teemu-tim-and-torin-to-the-open-policy-agent-community-2dbbfe494371)
  for more information.

See also, [Developer Documentation](./DEVELOPMENT.md).

S3 EOPA Data plugin

How it works:

AWS SDK v2 Default Credential Chain:
1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
2. Shared credentials/config files (~/.aws/credentials)
3. Web Identity Token (AWS_ROLE_ARN + AWS_WEB_IDENTITY_TOKEN_FILE) ← IRSA
4. ECS container credentials
5. EC2 instance metadata

So with my changes, when you omit access_id and secret, the SDK's default chain kicks in and automatically uses IRSA if those env vars are set by EKS.

The explicit IRSA config I added is only needed if:
- You want to override the environment variables with different values
- You're using web identity tokens outside standard EKS (custom setup)

For standard EKS IRSA, the SDK does it all directly. You just need:

plugins:
data:
s3.mydata:
type: s3
url: s3://my-bucket/data.json
path: data.s3

The previous implementation required access_id and secret, which forced static credentials and bypassed the SDK's default chain entirely. Now that they're optional, the SDK's
built-in IRSA support works automatically.


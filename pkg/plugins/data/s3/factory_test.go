// Copyright 2025 The OPA Authors
// SPDX-License-Identifier: Apache-2.0

package s3

import (
	"testing"

	inmem "github.com/open-policy-agent/eopa/pkg/storage"
	"github.com/open-policy-agent/opa/v1/plugins"
)

func TestS3ConfigEndpoint(t *testing.T) {
	raw := `
plugins:
  data:
    s3.foo:
`
	s3 := `      endpoint: "https://whatever"
      url: "s3://bucket"
      access_id: acc
      secret: sec
`
	path := `      path: s3.foo`

	mgr, err := plugins.New([]byte(raw+s3), "test-instance-id", inmem.New())
	if err != nil {
		t.Fatal(err)
	}
	dp, err := Factory().Validate(mgr, []byte(s3+path))
	if err != nil {
		t.Fatal(err)
	}
	act := dp.(Config)
	if exp, act := "https://whatever", act.endpoint; exp != act {
		t.Errorf("expected endpoint = %v, got %v", exp, act)
	}
}

func TestS3ConfigCredentials(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "static credentials valid",
			config: `url: "s3://bucket"
access_id: acc
secret: sec
path: s3.foo`,
			wantErr: "",
		},
		{
			name: "no credentials valid (uses env/IAM/IRSA)",
			config: `url: "s3://bucket"
path: s3.foo`,
			wantErr: "",
		},
		{
			name: "only access_id invalid",
			config: `url: "s3://bucket"
access_id: acc
path: s3.foo`,
			wantErr: "access_id and secret must both be provided or both be omitted",
		},
		{
			name: "only secret invalid",
			config: `url: "s3://bucket"
secret: sec
path: s3.foo`,
			wantErr: "access_id and secret must both be provided or both be omitted",
		},
		{
			name: "IRSA config valid",
			config: `url: "s3://bucket"
role_arn: "arn:aws:iam::123456789012:role/my-role"
web_identity_token_file: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
path: s3.foo`,
			wantErr: "",
		},
		{
			name: "IRSA with session name valid",
			config: `url: "s3://bucket"
role_arn: "arn:aws:iam::123456789012:role/my-role"
web_identity_token_file: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
role_session_name: "my-session"
path: s3.foo`,
			wantErr: "",
		},
		{
			name: "only role_arn invalid",
			config: `url: "s3://bucket"
role_arn: "arn:aws:iam::123456789012:role/my-role"
path: s3.foo`,
			wantErr: "role_arn and web_identity_token_file must both be provided or both be omitted",
		},
		{
			name: "only web_identity_token_file invalid",
			config: `url: "s3://bucket"
web_identity_token_file: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
path: s3.foo`,
			wantErr: "role_arn and web_identity_token_file must both be provided or both be omitted",
		},
		{
			name: "static and IRSA together valid",
			config: `url: "s3://bucket"
access_id: acc
secret: sec
role_arn: "arn:aws:iam::123456789012:role/my-role"
web_identity_token_file: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
path: s3.foo`,
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Factory().Validate(nil, []byte(tt.config))
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.wantErr)
				} else if err.Error() != tt.wantErr {
					t.Errorf("expected error %q, got %q", tt.wantErr, err.Error())
				}
			}
		})
	}
}

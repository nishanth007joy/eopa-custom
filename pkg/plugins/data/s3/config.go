// Copyright 2025 The OPA Authors
// SPDX-License-Identifier: Apache-2.0

package s3

import (
	"time"

	"github.com/open-policy-agent/opa/v1/storage"
)

const (
	AWSScheme = "s3"
	GCSScheme = "gs"
)

var (
	DefaultRegions = map[string]string{
		AWSScheme: "us-east-1",
		GCSScheme: "auto",
	}
	DefaultEndpoints = map[string]string{
		AWSScheme: "",
		GCSScheme: "https://storage.googleapis.com",
	}
)

// Config represents the configuration of the s3 data plugin
type Config struct {
	URL       string `json:"url"`
	Region    string `json:"region,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	AccessID  string `json:"access_id,omitempty"`
	Secret    string `json:"secret,omitempty"`
	ForcePath bool   `json:"force_path"`

	// IRSA (IAM Roles for Service Accounts) configuration
	// When running in EKS, these can be automatically populated from environment variables:
	// - AWS_ROLE_ARN
	// - AWS_WEB_IDENTITY_TOKEN_FILE
	// - AWS_ROLE_SESSION_NAME (optional, defaults to "eopa-session")
	RoleARN              string `json:"role_arn,omitempty"`
	WebIdentityTokenFile string `json:"web_identity_token_file,omitempty"`
	RoleSessionName      string `json:"role_session_name,omitempty"`

	Interval string `json:"polling_interval,omitempty"` // default 5m, min 10s
	Path     string `json:"path"`

	RegoTransformRule string `json:"rego_transform"`

	// inserted through Validate()
	bucket   string
	filepath string
	region   string
	endpoint string
	path     storage.Path
	interval time.Duration
}

func (c Config) Equal(other Config) bool {
	switch {
	case c.AccessID != other.AccessID:
	case c.RegoTransformRule != other.RegoTransformRule:
	case c.ForcePath != other.ForcePath:
	case c.Secret != other.Secret:
	case c.RoleARN != other.RoleARN:
	case c.WebIdentityTokenFile != other.WebIdentityTokenFile:
	case c.RoleSessionName != other.RoleSessionName:
	case c.bucket != other.bucket:
	case c.filepath != other.filepath:
	case c.region != other.region:
	case c.endpoint != other.endpoint:
	case c.Interval != other.Interval:
	default:
		return true
	}
	return false
}

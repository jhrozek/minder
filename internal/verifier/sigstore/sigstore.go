// Copyright 2023 Stacklok, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package sigstore provides a client for verifying artifacts using sigstore
package sigstore

import (
	"context"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/stacklok/minder/internal/verifier/sigstore/container"
	"github.com/stacklok/minder/internal/verifier/verifyif"
)

const (
	// SigstorePublicTrustedRootRepo is the public trusted root repository for sigstore
	SigstorePublicTrustedRootRepo = "tuf-repo-cdn.sigstore.dev"
)

// Sigstore is the sigstore verifier
type Sigstore struct {
	verifier *verify.SignedEntityVerifier
	authOpts []container.AuthMethod
}

var _ verifyif.ArtifactVerifier = (*Sigstore)(nil)

// New creates a new Sigstore verifier
func New(trustedRoot, cacheDir string, authOpts ...container.AuthMethod) (*Sigstore, error) {
	// init sigstore's verifier
	opts := tuf.DefaultOptions()
	opts.RepositoryBaseURL = "https://" + trustedRoot
	opts.CachePath = cacheDir
	client, err := tuf.New(opts)
	if err != nil {
		return nil, err
	}
	trustedrootJSON, err := client.GetTarget("trusted_root.json")
	if err != nil {
		return nil, err
	}

	trustedMaterial, err := root.NewTrustedRootFromJSON(trustedrootJSON)
	if err != nil {
		return nil, err
	}
	sev, err := verify.NewSignedEntityVerifier(trustedMaterial,
		verify.WithoutAnyObserverTimestampsInsecure(),
	)
	if err != nil {
		return nil, err
	}
	// return the verifier
	return &Sigstore{
		verifier: sev,
		authOpts: authOpts,
	}, nil
}

// VerifyContainer verifies a container artifact using sigstore
func (s *Sigstore) VerifyContainer(ctx context.Context, registry, owner, artifact, version string) (
	*verifyif.Result, error) {
	return container.Verify(ctx, s.verifier, registry, owner, artifact, version, s.authOpts...)
}

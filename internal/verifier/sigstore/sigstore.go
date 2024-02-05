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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/stacklok/minder/internal/verifier/sigstore/container"
	"github.com/stacklok/minder/internal/verifier/verifyif"
)

const (
	// SigstorePublicTrustedRootRepo is the public trusted root repository for sigstore
	SigstorePublicTrustedRootRepo = "tuf-repo-cdn.sigstore.dev"
	// LocalCacheDir is the local cache directory for the verifier
	LocalCacheDir = "/tmp/minder-cache"
)

const (
	newFilePerms = os.FileMode(0600)
	newDirPerms  = os.FileMode(0750)
)

// Sigstore is the sigstore verifier
type Sigstore struct {
	verifier *verify.SignedEntityVerifier
	authOpts []container.AuthMethod
	cacheDir string
}

var _ verifyif.ArtifactVerifier = (*Sigstore)(nil)

// New creates a new Sigstore verifier
func New(trustedRoot string, authOpts ...container.AuthMethod) (*Sigstore, error) {
	cacheDir, err := createTmpDir(LocalCacheDir, "sigstore")
	if err != nil {
		return nil, err
	}

	// init sigstore's verifier
	if err := seedRootJson(trustedRoot, cacheDir); err != nil {
		return nil, err
	}

	trustedrootJSON, err := tuf.GetTrustedrootJSON(trustedRoot, cacheDir)
	if err != nil {
		return nil, err
	}
	trustedMaterial, err := root.NewTrustedRootFromJSON(trustedrootJSON)
	if err != nil {
		return nil, err
	}
	/*
		sev, err := verify.NewSignedEntityVerifier(trustedMaterial, verify.WithSignedCertificateTimestamps(1),
			verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	*/
	sev, err := verify.NewSignedEntityVerifier(trustedMaterial, verify.WithSignedTimestamps(1))
	if err != nil {
		return nil, err
	}

	// return the verifier
	return &Sigstore{
		verifier: sev,
		authOpts: authOpts,
		cacheDir: cacheDir,
	}, nil
}

// Verify verifies an artifact
func (s *Sigstore) Verify(ctx context.Context, artifactType verifyif.ArtifactType, registry verifyif.ArtifactRegistry,
	owner, artifact, version string) ([]verifyif.Result, error) {
	var err error
	var res []verifyif.Result
	// Sanitize the input
	sanitizeInput(&registry, &owner)

	// Process verification based on the artifact type
	switch artifactType {
	case verifyif.ArtifactTypeContainer:
		res, err = s.VerifyContainer(ctx, string(registry), owner, artifact, version)
	default:
		err = fmt.Errorf("unknown artifact type: %s", artifactType)
	}

	return res, err
}

// VerifyContainer verifies a container artifact using sigstore
func (s *Sigstore) VerifyContainer(ctx context.Context, registry, owner, artifact, version string) (
	[]verifyif.Result, error) {
	return container.Verify(ctx, s.verifier, registry, owner, artifact, version, s.authOpts...)
}

// ClearCache clears the sigstore cache
func (s *Sigstore) ClearCache() {
	if err := os.RemoveAll(s.cacheDir); err != nil {
		log.Err(err).Msg("error deleting temporary sigstore cache directory")
	}
}

func createTmpDir(basePath, prefix string) (string, error) {
	// ensure the path exists
	err := os.MkdirAll(basePath, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("failed to ensure path for temporary sigstore cache directory: %w", err)
	}
	// create the temporary directory
	tmpDir, err := os.MkdirTemp(basePath, prefix)
	if err != nil {
		return "", fmt.Errorf("failed to create temporary sigstore cache directory: %w", err)
	}
	return tmpDir, nil
}

// sanitizeInput sanitizes the input parameters
func sanitizeInput(registry *verifyif.ArtifactRegistry, owner *string) {
	// Default the registry to GHCR for the time being
	if *registry == "" {
		*registry = verifyif.ArtifactRegistryGHCR
	}
	// (jaosorior): The owner can't be upper-cased, normalize the owner.
	*owner = strings.ToLower(*owner)
}

func seedRootJson(tufRepo, cacheDir string) error {
	// sigstore-go has a copy of the root.json for the public sigstore
	// instance embedded. Nothing to do.
	if tufRepo == SigstorePublicTrustedRootRepo {
		return nil
	}

	rootJson, err := getRootJson(tufRepo)
	if err != nil {
		return err
	}

	return writeRootJson(tufRepo, cacheDir, rootJson)
}

func getRootJson(tufRepo string) ([]byte, error) {
	tufRoot, err := normalizeUrl(tufRepo)
	if err != nil {
		return []byte{}, err
	}

	resp, err := http.Get(tufRoot) // #nosec G107 - this URL is user-provided and affects only evaluation in that single project
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func normalizeUrl(tufRoot string) (string, error) {
	if !strings.Contains(tufRoot, "://") {
		// this is likely a naive way of checking for the schema
		tufRoot = "https://" + tufRoot
	}

	parsedUrl, err := url.Parse(tufRoot)
	if err != nil {
		return "", err
	}

	if parsedUrl.Scheme == "" {
		parsedUrl.Scheme = "https"
	} else if parsedUrl.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme: %s", parsedUrl.Scheme)
	}

	if strings.HasSuffix(parsedUrl.Path, "../") {
		return "", errors.New("invalid path")
	}

	if parsedUrl.RawQuery != "" || parsedUrl.Fragment != "" {
		return "", errors.New("invalid query or fragment")
	}

	if parsedUrl.Path == "" {
		parsedUrl.Path = "/1.root.json"
	}

	return parsedUrl.String(), nil
}

func writeRootJson(tufRepo, cacheDir string, rootJson []byte) error {
	tufPath := path.Join(cacheDir, tufRepo)
	fi, err := os.Stat(tufPath)
	if errors.Is(err, fs.ErrNotExist) {
		if err = os.MkdirAll(tufPath, newDirPerms); err != nil {
			return fmt.Errorf("error creating directory for metadata cache: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("error getting FileInfo for %s: %w", tufPath, err)
	} else {
		if !fi.IsDir() {
			return fmt.Errorf("can not open %s, not a directory", tufPath)
		}
		// Verify file mode is not too permissive.
		if err = ensureMaxPermissions(fi, newDirPerms); err != nil {
			return err
		}
	}

	rootPath := path.Join(tufPath, tuf.RootTUFPath)
	return os.WriteFile(rootPath, rootJson, newFilePerms)
}

// taken from go-tuf/internal/fsutil/perm.go
//
// EnsureMaxPermissions tests the provided file info, returning an error if the
// file's permission bits contain excess permissions not set in maxPerms.
//
// For example, a file with permissions -rw------- will successfully validate
// with maxPerms -rw-r--r-- or -rw-rw-r--, but will not validate with maxPerms
// -r-------- (due to excess --w------- permission) or --w------- (due to
// excess -r-------- permission).
//
// Only permission bits of the file modes are considered.
func ensureMaxPermissions(fi os.FileInfo, maxPerms os.FileMode) error {
	gotPerm := fi.Mode().Perm()
	forbiddenPerms := (^maxPerms).Perm()
	excessPerms := gotPerm & forbiddenPerms

	if excessPerms != 0 {
		return fmt.Errorf("permission bits for file %v failed validation: want at most %v, got %v with excess perms %v", fi.Name(), maxPerms.Perm(), gotPerm, excessPerms)
	}

	return nil
}

//
// Copyright 2024 Stacklok, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:generate go run go.uber.org/mock/mockgen -package mock_$GOPACKAGE -destination=./mock/$GOFILE -source=./$GOFILE

// Package selectors provides utilities for selecting entities based on profiles using CEL
package selectors

import (
	"fmt"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"google.golang.org/protobuf/proto"

	"github.com/stacklok/minder/internal/engine/entities"
	minderv1 "github.com/stacklok/minder/pkg/api/protobuf/go/minder/v1"
)

// celEnvFactory is an interface for creating CEL environments
// for an entity. Each entity must implement this interface to be
// usable in selectors
type celEnvFactory interface {
	createEnv() (*cel.Env, error)
}

// genericEnvFactory is a factory for creating a CEL environment
// for the generic SelectorEntity type
type genericEnvFactory struct{}

func (_ *genericEnvFactory) createEnv() (*cel.Env, error) {
	return newEnvForEntity(
		"entity",
		&minderv1.SelectorEntity{},
		"minder.v1.SelectorEntity")
}

// repoEnvFactory is a factory for creating a CEL environment
// for the SelectorRepository type representing a repository
type repoEnvFactory struct{}

func (_ *repoEnvFactory) createEnv() (*cel.Env, error) {
	return newEnvForEntity(
		"repository",
		&minderv1.SelectorEntity_SelectorRepository{},
		"minder.v1.SelectorEntity.SelectorRepository")
}

// artifactEnvFactory is a factory for creating a CEL environment
// for the SelectorArtifact type representing an artifact
type artifactEnvFactory struct{}

func (_ *artifactEnvFactory) createEnv() (*cel.Env, error) {
	return newEnvForEntity(
		"artifact",
		&minderv1.SelectorEntity_SelectorArtifact{},
		"minder.v1.SelectorEntity.SelectorArtifact")
}

// newEnvForEntity creates a new CEL environment for an entity. All environments are allowed to
// use the generic "entity" variable plus the specific entity type is also declared as variable
// with the appropriate type.
func newEnvForEntity(varName string, typ any, typName string) (*cel.Env, error) {
	entityPtr := &minderv1.SelectorEntity{}

	env, err := cel.NewEnv(
		cel.Types(typ), cel.Types(&minderv1.SelectorEntity{}),
		cel.Declarations(
			decls.NewVar("entity",
				decls.NewObjectType(string(entityPtr.ProtoReflect().Descriptor().FullName())),
			),
			decls.NewVar(varName,
				decls.NewObjectType(typName),
			),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment for %s: %v", varName, err)
	}

	return env, nil
}

type compiledSelector = cel.Program

// SelectionBuilder is an interface for creating Selections (a collection of compiled CEL expressions)
// for an entity type. This is what the user of this module uses. The interface makes it easier to pass
// mocks by the user of this module.
type SelectionBuilder interface {
	NewSelectionFromProfile(minderv1.Entity, []*minderv1.Profile_Selector) (Selection, error)
}

// Env is a struct that holds the CEL environments for each entity type and the factories for creating
type Env struct {
	// entityEnvs is a map of entity types to their respective CEL environments. We keep them cached
	// and lazy-initialize on first use
	entityEnvs map[minderv1.Entity]*entityEnvCache
	// factories is a map of entity types to their respective factories for creating CEL environments
	factories map[minderv1.Entity]celEnvFactory
}

// entityEnvCache is a struct that holds a CEL environment for lazy-initialization. Since the initialization
// is done only once, we also keep track of the error
type entityEnvCache struct {
	once sync.Once
	env  *cel.Env
	err  error
}

// NewEnv creates a new Env struct with the default factories for each entity type. The factories
// are used on first access to create the CEL environments for each entity type.
func NewEnv() (*Env, error) {
	factoryMap := map[minderv1.Entity]celEnvFactory{
		minderv1.Entity_ENTITY_UNSPECIFIED:  &genericEnvFactory{},
		minderv1.Entity_ENTITY_REPOSITORIES: &repoEnvFactory{},
		minderv1.Entity_ENTITY_ARTIFACTS:    &artifactEnvFactory{},
	}

	entityEnvs := make(map[minderv1.Entity]*entityEnvCache, len(factoryMap))
	for entity := range factoryMap {
		entityEnvs[entity] = &entityEnvCache{}
	}

	return &Env{
		entityEnvs: entityEnvs,
		factories:  factoryMap,
	}, nil
}

// NewSelectionFromProfile creates a new Selection (compiled CEL programs for that entity type)
// from a profile
func (e *Env) NewSelectionFromProfile(
	entityType minderv1.Entity,
	profileSelection []*minderv1.Profile_Selector,
) (Selection, error) {
	selector := make([]cel.Program, 0, len(profileSelection))

	for _, sel := range profileSelection {
		ent := minderv1.EntityFromString(sel.GetEntity())
		if ent != entityType && ent != minderv1.Entity_ENTITY_UNSPECIFIED {
			continue
		}

		program, err := e.compileSelectorForEntity(sel.Selector, ent)
		if err != nil {
			return nil, fmt.Errorf("failed to compile selector %q: %w", sel.Selector, err)
		}

		selector = append(selector, program)
	}

	return &EntitySelection{
		selector: selector,
		entity:   entityType,
	}, nil
}

// compileSelectorForEntity compiles a selector expression for a given entity type into a CEL program
func (e *Env) compileSelectorForEntity(selector string, entityType minderv1.Entity) (compiledSelector, error) {
	env, err := e.envForEntity(entityType)
	if err != nil {
		return nil, fmt.Errorf("failed to get environment for entity %v: %w", entityType, err)
	}

	ast, issues := env.Parse(selector)
	if issues.Err() != nil {
		return nil, fmt.Errorf("failed to parse expression %q: %w", selector, issues.Err())
	}

	checked, issues := env.Check(ast)
	if issues.Err() != nil {
		return nil, fmt.Errorf("failed to check expression %q: %w", selector, issues.Err())
	}

	program, err := env.Program(checked)
	if err != nil {
		return nil, fmt.Errorf("failed to create program for expression %q: %w", selector, err)
	}

	return program, nil
}

// envForEntity gets the CEL environment for a given entity type. If the environment is not cached,
// it creates it using the factory for that entity type.
func (e *Env) envForEntity(entity minderv1.Entity) (*cel.Env, error) {
	cache, ok := e.entityEnvs[entity]
	if !ok {
		return nil, fmt.Errorf("no cache found for entity %v", entity)
	}

	cache.once.Do(func() {
		cache.env, cache.err = e.factories[entity].createEnv()
	})

	return cache.env, cache.err
}

// entityInfoConverter is an interface for converting an entity from an EntityInfoWrapper to a SelectorEntity
type entityInfoConverter interface {
	toSelectorEntity(entity proto.Message) *minderv1.SelectorEntity
}

type repositoryInfoConverter struct{}

func (_ *repositoryInfoConverter) toSelectorEntity(entity proto.Message) *minderv1.SelectorEntity {
	r, ok := entity.(*minderv1.Repository)
	if !ok {
		return nil
	}

	return &minderv1.SelectorEntity{
		EntityType: minderv1.Entity_ENTITY_REPOSITORIES,
		Name:       fmt.Sprintf("%s/%s", r.GetOwner(), r.GetName()),
		Entity: &minderv1.SelectorEntity_Repository{
			Repository: &minderv1.SelectorEntity_SelectorRepository{
				Name:      fmt.Sprintf("%s/%s", r.GetOwner(), r.GetName()),
				RepoName:  r.GetName(),
				Owner:     r.GetOwner(),
				IsFork:    proto.Bool(r.GetIsFork()),
				IsPrivate: proto.Bool(r.GetIsPrivate()),
			},
		},
	}
}

type artifactInfoConverter struct{}

func (_ *artifactInfoConverter) toSelectorEntity(entity proto.Message) *minderv1.SelectorEntity {
	a, ok := entity.(*minderv1.Artifact)
	if !ok {
		return nil
	}

	return &minderv1.SelectorEntity{
		EntityType: minderv1.Entity_ENTITY_ARTIFACTS,
		Name:       fmt.Sprintf("%s/%s", a.GetOwner(), a.GetName()),
		Entity: &minderv1.SelectorEntity_Artifact{
			Artifact: &minderv1.SelectorEntity_SelectorArtifact{
				Name:         fmt.Sprintf("%s/%s", a.GetOwner(), a.GetName()),
				ArtifactName: a.GetName(),
				Owner:        a.GetOwner(),
				Type:         a.GetType(),
			},
		},
	}
}

// converterFactory is a map of entity types to their respective converters
type converterFactory struct {
	converters map[minderv1.Entity]entityInfoConverter
}

// newConverterFactory creates a new converterFactory with the default converters for each entity type
func newConverterFactory() *converterFactory {
	return &converterFactory{
		converters: map[minderv1.Entity]entityInfoConverter{
			minderv1.Entity_ENTITY_REPOSITORIES: &repositoryInfoConverter{},
			minderv1.Entity_ENTITY_ARTIFACTS:    &artifactInfoConverter{},
		},
	}
}

func (cf *converterFactory) getConverter(entityType minderv1.Entity) (entityInfoConverter, error) {
	conv, ok := cf.converters[entityType]
	if !ok {
		return nil, fmt.Errorf("no converter found for entity type %v", entityType)
	}

	return conv, nil
}

func newSelectorEntity(eiw *entities.EntityInfoWrapper) *minderv1.SelectorEntity {
	if eiw == nil {
		return nil
	}

	convertFactory := newConverterFactory()
	conv, err := convertFactory.getConverter(eiw.Type)
	if err != nil {
		return nil
	}

	return conv.toSelectorEntity(eiw.Entity)
}

// Selection is an interface for selecting entities based on a profile
type Selection interface {
	Select(*minderv1.SelectorEntity) (bool, error)
	SelectEiw(*entities.EntityInfoWrapper) (bool, error)
}

// EntitySelection is a struct that holds the compiled CEL expressions for a given entity type
type EntitySelection struct {
	selector []cel.Program
	entity   minderv1.Entity
}

// Select return true if the entity matches all the compiled expressions and false otherwise
func (s *EntitySelection) Select(se *minderv1.SelectorEntity) (bool, error) {
	if se == nil {
		return false, fmt.Errorf("input entity is nil")
	}

	for _, sel := range s.selector {
		entityMap, err := inputAsMap(se)
		if err != nil {
			return false, fmt.Errorf("failed to convert input to map: %w", err)
		}

		out, _, err := sel.Eval(entityMap)
		if err != nil {
			return false, fmt.Errorf("failed to evaluate Expression: %w", err)
		}

		if out.Type() != cel.BoolType {
			return false, fmt.Errorf("expression did not evaluate to a boolean: %v", out)
		}

		if !out.Value().(bool) {
			return false, nil
		}
	}

	return true, nil
}

// SelectEiw selects an entity based on an EntityInfoWrapper. It is a convenience method
// around Select that creates a SelectorEntity from the EntityInfoWrapper
func (s *EntitySelection) SelectEiw(eiw *entities.EntityInfoWrapper) (bool, error) {
	se := newSelectorEntity(eiw)
	if se == nil {
		return false, fmt.Errorf("failed to create SelectorEntity from EntityInfoWrapper")
	}

	return s.Select(se)
}

func inputAsMap(se *minderv1.SelectorEntity) (map[string]any, error) {
	var value any

	key := se.GetEntityType().ToString()

	// FIXME(jakub): I tried to be smart and code something up using protoreflect and WhichOneOf but didn't
	// make it work. Maybe someone smarter than me can.
	// nolint:exhaustive
	switch se.GetEntityType() {
	case minderv1.Entity_ENTITY_REPOSITORIES:
		value = se.GetRepository()
	case minderv1.Entity_ENTITY_ARTIFACTS:
		value = se.GetArtifact()
	default:
		return nil, fmt.Errorf("unsupported entity type [%d]: %s", se.GetEntityType(), se.GetEntityType().ToString())
	}

	return map[string]any{
		key:      value,
		"entity": se,
	}, nil
}

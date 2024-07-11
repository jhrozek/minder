// Code generated by MockGen. DO NOT EDIT.
// Source: ./interface.go
//
// Generated by this command:
//
//	mockgen -package mock_selectors -destination=./mock/interface.go -source=./interface.go
//

// Package mock_selectors is a generated GoMock package.
package mock_selectors

import (
	context "context"
	reflect "reflect"

	proto "github.com/stacklok/minder/internal/proto"
	v1 "github.com/stacklok/minder/pkg/api/protobuf/go/minder/v1"
	gomock "go.uber.org/mock/gomock"
)

// MockRepoSelectorConverter is a mock of RepoSelectorConverter interface.
type MockRepoSelectorConverter struct {
	ctrl     *gomock.Controller
	recorder *MockRepoSelectorConverterMockRecorder
}

// MockRepoSelectorConverterMockRecorder is the mock recorder for MockRepoSelectorConverter.
type MockRepoSelectorConverterMockRecorder struct {
	mock *MockRepoSelectorConverter
}

// NewMockRepoSelectorConverter creates a new mock instance.
func NewMockRepoSelectorConverter(ctrl *gomock.Controller) *MockRepoSelectorConverter {
	mock := &MockRepoSelectorConverter{ctrl: ctrl}
	mock.recorder = &MockRepoSelectorConverterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRepoSelectorConverter) EXPECT() *MockRepoSelectorConverterMockRecorder {
	return m.recorder
}

// CanImplement mocks base method.
func (m *MockRepoSelectorConverter) CanImplement(trait v1.ProviderType) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CanImplement", trait)
	ret0, _ := ret[0].(bool)
	return ret0
}

// CanImplement indicates an expected call of CanImplement.
func (mr *MockRepoSelectorConverterMockRecorder) CanImplement(trait any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CanImplement", reflect.TypeOf((*MockRepoSelectorConverter)(nil).CanImplement), trait)
}

// RepoToSelectorEntity mocks base method.
func (m *MockRepoSelectorConverter) RepoToSelectorEntity(ctx context.Context, repo *v1.Repository) *proto.SelectorEntity {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RepoToSelectorEntity", ctx, repo)
	ret0, _ := ret[0].(*proto.SelectorEntity)
	return ret0
}

// RepoToSelectorEntity indicates an expected call of RepoToSelectorEntity.
func (mr *MockRepoSelectorConverterMockRecorder) RepoToSelectorEntity(ctx, repo any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RepoToSelectorEntity", reflect.TypeOf((*MockRepoSelectorConverter)(nil).RepoToSelectorEntity), ctx, repo)
}

// MockArtifactSelectorConverter is a mock of ArtifactSelectorConverter interface.
type MockArtifactSelectorConverter struct {
	ctrl     *gomock.Controller
	recorder *MockArtifactSelectorConverterMockRecorder
}

// MockArtifactSelectorConverterMockRecorder is the mock recorder for MockArtifactSelectorConverter.
type MockArtifactSelectorConverterMockRecorder struct {
	mock *MockArtifactSelectorConverter
}

// NewMockArtifactSelectorConverter creates a new mock instance.
func NewMockArtifactSelectorConverter(ctrl *gomock.Controller) *MockArtifactSelectorConverter {
	mock := &MockArtifactSelectorConverter{ctrl: ctrl}
	mock.recorder = &MockArtifactSelectorConverterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockArtifactSelectorConverter) EXPECT() *MockArtifactSelectorConverterMockRecorder {
	return m.recorder
}

// ArtifactToSelectorEntity mocks base method.
func (m *MockArtifactSelectorConverter) ArtifactToSelectorEntity(ctx context.Context, artifact *v1.Artifact) *proto.SelectorEntity {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ArtifactToSelectorEntity", ctx, artifact)
	ret0, _ := ret[0].(*proto.SelectorEntity)
	return ret0
}

// ArtifactToSelectorEntity indicates an expected call of ArtifactToSelectorEntity.
func (mr *MockArtifactSelectorConverterMockRecorder) ArtifactToSelectorEntity(ctx, artifact any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ArtifactToSelectorEntity", reflect.TypeOf((*MockArtifactSelectorConverter)(nil).ArtifactToSelectorEntity), ctx, artifact)
}

// CanImplement mocks base method.
func (m *MockArtifactSelectorConverter) CanImplement(trait v1.ProviderType) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CanImplement", trait)
	ret0, _ := ret[0].(bool)
	return ret0
}

// CanImplement indicates an expected call of CanImplement.
func (mr *MockArtifactSelectorConverterMockRecorder) CanImplement(trait any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CanImplement", reflect.TypeOf((*MockArtifactSelectorConverter)(nil).CanImplement), trait)
}

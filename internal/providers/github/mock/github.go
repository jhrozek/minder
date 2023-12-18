// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/providers/v1/providers.go

// Package mockgh is a generated GoMock package.
package mockgh

import (
	context "context"
	http "net/http"
	reflect "reflect"

	git "github.com/go-git/go-git/v5"
	gomock "github.com/golang/mock/gomock"
	github "github.com/google/go-github/v56/github"
	v1 "github.com/stacklok/minder/pkg/api/protobuf/go/minder/v1"
)

// MockProvider is a mock of Provider interface.
type MockProvider struct {
	ctrl     *gomock.Controller
	recorder *MockProviderMockRecorder
}

// MockProviderMockRecorder is the mock recorder for MockProvider.
type MockProviderMockRecorder struct {
	mock *MockProvider
}

// NewMockProvider creates a new mock instance.
func NewMockProvider(ctrl *gomock.Controller) *MockProvider {
	mock := &MockProvider{ctrl: ctrl}
	mock.recorder = &MockProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockProvider) EXPECT() *MockProviderMockRecorder {
	return m.recorder
}

// GetToken mocks base method.
func (m *MockProvider) GetToken() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetToken")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetToken indicates an expected call of GetToken.
func (mr *MockProviderMockRecorder) GetToken() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetToken", reflect.TypeOf((*MockProvider)(nil).GetToken))
}

// MockGit is a mock of Git interface.
type MockGit struct {
	ctrl     *gomock.Controller
	recorder *MockGitMockRecorder
}

// MockGitMockRecorder is the mock recorder for MockGit.
type MockGitMockRecorder struct {
	mock *MockGit
}

// NewMockGit creates a new mock instance.
func NewMockGit(ctrl *gomock.Controller) *MockGit {
	mock := &MockGit{ctrl: ctrl}
	mock.recorder = &MockGitMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockGit) EXPECT() *MockGitMockRecorder {
	return m.recorder
}

// Clone mocks base method.
func (m *MockGit) Clone(ctx context.Context, url, branch string) (*git.Repository, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Clone", ctx, url, branch)
	ret0, _ := ret[0].(*git.Repository)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Clone indicates an expected call of Clone.
func (mr *MockGitMockRecorder) Clone(ctx, url, branch interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Clone", reflect.TypeOf((*MockGit)(nil).Clone), ctx, url, branch)
}

// GetToken mocks base method.
func (m *MockGit) GetToken() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetToken")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetToken indicates an expected call of GetToken.
func (mr *MockGitMockRecorder) GetToken() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetToken", reflect.TypeOf((*MockGit)(nil).GetToken))
}

// MockREST is a mock of REST interface.
type MockREST struct {
	ctrl     *gomock.Controller
	recorder *MockRESTMockRecorder
}

// MockRESTMockRecorder is the mock recorder for MockREST.
type MockRESTMockRecorder struct {
	mock *MockREST
}

// NewMockREST creates a new mock instance.
func NewMockREST(ctrl *gomock.Controller) *MockREST {
	mock := &MockREST{ctrl: ctrl}
	mock.recorder = &MockRESTMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockREST) EXPECT() *MockRESTMockRecorder {
	return m.recorder
}

// Do mocks base method.
func (m *MockREST) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Do", ctx, req)
	ret0, _ := ret[0].(*http.Response)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Do indicates an expected call of Do.
func (mr *MockRESTMockRecorder) Do(ctx, req interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Do", reflect.TypeOf((*MockREST)(nil).Do), ctx, req)
}

// GetBaseURL mocks base method.
func (m *MockREST) GetBaseURL() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBaseURL")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetBaseURL indicates an expected call of GetBaseURL.
func (mr *MockRESTMockRecorder) GetBaseURL() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBaseURL", reflect.TypeOf((*MockREST)(nil).GetBaseURL))
}

// GetToken mocks base method.
func (m *MockREST) GetToken() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetToken")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetToken indicates an expected call of GetToken.
func (mr *MockRESTMockRecorder) GetToken() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetToken", reflect.TypeOf((*MockREST)(nil).GetToken))
}

// NewRequest mocks base method.
func (m *MockREST) NewRequest(method, url string, body any) (*http.Request, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewRequest", method, url, body)
	ret0, _ := ret[0].(*http.Request)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewRequest indicates an expected call of NewRequest.
func (mr *MockRESTMockRecorder) NewRequest(method, url, body interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewRequest", reflect.TypeOf((*MockREST)(nil).NewRequest), method, url, body)
}

// MockRepoLister is a mock of RepoLister interface.
type MockRepoLister struct {
	ctrl     *gomock.Controller
	recorder *MockRepoListerMockRecorder
}

// MockRepoListerMockRecorder is the mock recorder for MockRepoLister.
type MockRepoListerMockRecorder struct {
	mock *MockRepoLister
}

// NewMockRepoLister creates a new mock instance.
func NewMockRepoLister(ctrl *gomock.Controller) *MockRepoLister {
	mock := &MockRepoLister{ctrl: ctrl}
	mock.recorder = &MockRepoListerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRepoLister) EXPECT() *MockRepoListerMockRecorder {
	return m.recorder
}

// GetToken mocks base method.
func (m *MockRepoLister) GetToken() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetToken")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetToken indicates an expected call of GetToken.
func (mr *MockRepoListerMockRecorder) GetToken() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetToken", reflect.TypeOf((*MockRepoLister)(nil).GetToken))
}

// ListOrganizationRepsitories mocks base method.
func (m *MockRepoLister) ListOrganizationRepsitories(arg0 context.Context, arg1 string) ([]*v1.Repository, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListOrganizationRepsitories", arg0, arg1)
	ret0, _ := ret[0].([]*v1.Repository)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListOrganizationRepsitories indicates an expected call of ListOrganizationRepsitories.
func (mr *MockRepoListerMockRecorder) ListOrganizationRepsitories(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListOrganizationRepsitories", reflect.TypeOf((*MockRepoLister)(nil).ListOrganizationRepsitories), arg0, arg1)
}

// ListUserRepositories mocks base method.
func (m *MockRepoLister) ListUserRepositories(arg0 context.Context, arg1 string) ([]*v1.Repository, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListUserRepositories", arg0, arg1)
	ret0, _ := ret[0].([]*v1.Repository)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListUserRepositories indicates an expected call of ListUserRepositories.
func (mr *MockRepoListerMockRecorder) ListUserRepositories(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListUserRepositories", reflect.TypeOf((*MockRepoLister)(nil).ListUserRepositories), arg0, arg1)
}

// MockGitHub is a mock of GitHub interface.
type MockGitHub struct {
	ctrl     *gomock.Controller
	recorder *MockGitHubMockRecorder
}

// MockGitHubMockRecorder is the mock recorder for MockGitHub.
type MockGitHubMockRecorder struct {
	mock *MockGitHub
}

// NewMockGitHub creates a new mock instance.
func NewMockGitHub(ctrl *gomock.Controller) *MockGitHub {
	mock := &MockGitHub{ctrl: ctrl}
	mock.recorder = &MockGitHubMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockGitHub) EXPECT() *MockGitHubMockRecorder {
	return m.recorder
}

// CloseSecurityAdvisory mocks base method.
func (m *MockGitHub) CloseSecurityAdvisory(ctx context.Context, owner, repo, id string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CloseSecurityAdvisory", ctx, owner, repo, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// CloseSecurityAdvisory indicates an expected call of CloseSecurityAdvisory.
func (mr *MockGitHubMockRecorder) CloseSecurityAdvisory(ctx, owner, repo, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CloseSecurityAdvisory", reflect.TypeOf((*MockGitHub)(nil).CloseSecurityAdvisory), ctx, owner, repo, id)
}

// CreateComment mocks base method.
func (m *MockGitHub) CreateComment(ctx context.Context, owner, repo string, number int, comment string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateComment", ctx, owner, repo, number, comment)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateComment indicates an expected call of CreateComment.
func (mr *MockGitHubMockRecorder) CreateComment(ctx, owner, repo, number, comment interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateComment", reflect.TypeOf((*MockGitHub)(nil).CreateComment), ctx, owner, repo, number, comment)
}

// CreateHook mocks base method.
func (m *MockGitHub) CreateHook(ctx context.Context, owner, repo string, hook *github.Hook) (*github.Hook, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateHook", ctx, owner, repo, hook)
	ret0, _ := ret[0].(*github.Hook)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateHook indicates an expected call of CreateHook.
func (mr *MockGitHubMockRecorder) CreateHook(ctx, owner, repo, hook interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateHook", reflect.TypeOf((*MockGitHub)(nil).CreateHook), ctx, owner, repo, hook)
}

// CreatePullRequest mocks base method.
func (m *MockGitHub) CreatePullRequest(ctx context.Context, owner, repo, title, body, head, base string) (*github.PullRequest, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreatePullRequest", ctx, owner, repo, title, body, head, base)
	ret0, _ := ret[0].(*github.PullRequest)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreatePullRequest indicates an expected call of CreatePullRequest.
func (mr *MockGitHubMockRecorder) CreatePullRequest(ctx, owner, repo, title, body, head, base interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreatePullRequest", reflect.TypeOf((*MockGitHub)(nil).CreatePullRequest), ctx, owner, repo, title, body, head, base)
}

// CreateReview mocks base method.
func (m *MockGitHub) CreateReview(arg0 context.Context, arg1, arg2 string, arg3 int, arg4 *github.PullRequestReviewRequest) (*github.PullRequestReview, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateReview", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(*github.PullRequestReview)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateReview indicates an expected call of CreateReview.
func (mr *MockGitHubMockRecorder) CreateReview(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateReview", reflect.TypeOf((*MockGitHub)(nil).CreateReview), arg0, arg1, arg2, arg3, arg4)
}

// CreateSecurityAdvisory mocks base method.
func (m *MockGitHub) CreateSecurityAdvisory(ctx context.Context, owner, repo, severity, summary, description string, v []*github.AdvisoryVulnerability) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateSecurityAdvisory", ctx, owner, repo, severity, summary, description, v)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateSecurityAdvisory indicates an expected call of CreateSecurityAdvisory.
func (mr *MockGitHubMockRecorder) CreateSecurityAdvisory(ctx, owner, repo, severity, summary, description, v interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateSecurityAdvisory", reflect.TypeOf((*MockGitHub)(nil).CreateSecurityAdvisory), ctx, owner, repo, severity, summary, description, v)
}

// DeleteHook mocks base method.
func (m *MockGitHub) DeleteHook(ctx context.Context, owner, repo string, id int64) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteHook", ctx, owner, repo, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteHook indicates an expected call of DeleteHook.
func (mr *MockGitHubMockRecorder) DeleteHook(ctx, owner, repo, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteHook", reflect.TypeOf((*MockGitHub)(nil).DeleteHook), ctx, owner, repo, id)
}

// DismissReview mocks base method.
func (m *MockGitHub) DismissReview(arg0 context.Context, arg1, arg2 string, arg3 int, arg4 int64, arg5 *github.PullRequestReviewDismissalRequest) (*github.PullRequestReview, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DismissReview", arg0, arg1, arg2, arg3, arg4, arg5)
	ret0, _ := ret[0].(*github.PullRequestReview)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DismissReview indicates an expected call of DismissReview.
func (mr *MockGitHubMockRecorder) DismissReview(arg0, arg1, arg2, arg3, arg4, arg5 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DismissReview", reflect.TypeOf((*MockGitHub)(nil).DismissReview), arg0, arg1, arg2, arg3, arg4, arg5)
}

// Do mocks base method.
func (m *MockGitHub) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Do", ctx, req)
	ret0, _ := ret[0].(*http.Response)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Do indicates an expected call of Do.
func (mr *MockGitHubMockRecorder) Do(ctx, req interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Do", reflect.TypeOf((*MockGitHub)(nil).Do), ctx, req)
}

// GetAuthenticatedUser mocks base method.
func (m *MockGitHub) GetAuthenticatedUser(arg0 context.Context) (*github.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAuthenticatedUser", arg0)
	ret0, _ := ret[0].(*github.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAuthenticatedUser indicates an expected call of GetAuthenticatedUser.
func (mr *MockGitHubMockRecorder) GetAuthenticatedUser(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAuthenticatedUser", reflect.TypeOf((*MockGitHub)(nil).GetAuthenticatedUser), arg0)
}

// GetBaseURL mocks base method.
func (m *MockGitHub) GetBaseURL() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBaseURL")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetBaseURL indicates an expected call of GetBaseURL.
func (mr *MockGitHubMockRecorder) GetBaseURL() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBaseURL", reflect.TypeOf((*MockGitHub)(nil).GetBaseURL))
}

// GetBranchProtection mocks base method.
func (m *MockGitHub) GetBranchProtection(arg0 context.Context, arg1, arg2, arg3 string) (*github.Protection, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBranchProtection", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(*github.Protection)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetBranchProtection indicates an expected call of GetBranchProtection.
func (mr *MockGitHubMockRecorder) GetBranchProtection(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBranchProtection", reflect.TypeOf((*MockGitHub)(nil).GetBranchProtection), arg0, arg1, arg2, arg3)
}

// GetOwner mocks base method.
func (m *MockGitHub) GetOwner() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOwner")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetOwner indicates an expected call of GetOwner.
func (mr *MockGitHubMockRecorder) GetOwner() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOwner", reflect.TypeOf((*MockGitHub)(nil).GetOwner))
}

// GetPackageByName mocks base method.
func (m *MockGitHub) GetPackageByName(arg0 context.Context, arg1 bool, arg2, arg3, arg4 string) (*github.Package, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPackageByName", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(*github.Package)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPackageByName indicates an expected call of GetPackageByName.
func (mr *MockGitHubMockRecorder) GetPackageByName(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPackageByName", reflect.TypeOf((*MockGitHub)(nil).GetPackageByName), arg0, arg1, arg2, arg3, arg4)
}

// GetPackageVersionById mocks base method.
func (m *MockGitHub) GetPackageVersionById(arg0 context.Context, arg1 bool, arg2, arg3, arg4 string, arg5 int64) (*github.PackageVersion, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPackageVersionById", arg0, arg1, arg2, arg3, arg4, arg5)
	ret0, _ := ret[0].(*github.PackageVersion)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPackageVersionById indicates an expected call of GetPackageVersionById.
func (mr *MockGitHubMockRecorder) GetPackageVersionById(arg0, arg1, arg2, arg3, arg4, arg5 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPackageVersionById", reflect.TypeOf((*MockGitHub)(nil).GetPackageVersionById), arg0, arg1, arg2, arg3, arg4, arg5)
}

// GetPackageVersionByTag mocks base method.
func (m *MockGitHub) GetPackageVersionByTag(arg0 context.Context, arg1 bool, arg2, arg3, arg4, arg5 string) (*github.PackageVersion, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPackageVersionByTag", arg0, arg1, arg2, arg3, arg4, arg5)
	ret0, _ := ret[0].(*github.PackageVersion)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPackageVersionByTag indicates an expected call of GetPackageVersionByTag.
func (mr *MockGitHubMockRecorder) GetPackageVersionByTag(arg0, arg1, arg2, arg3, arg4, arg5 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPackageVersionByTag", reflect.TypeOf((*MockGitHub)(nil).GetPackageVersionByTag), arg0, arg1, arg2, arg3, arg4, arg5)
}

// GetPackageVersions mocks base method.
func (m *MockGitHub) GetPackageVersions(arg0 context.Context, arg1 bool, arg2, arg3, arg4 string) ([]*github.PackageVersion, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPackageVersions", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].([]*github.PackageVersion)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPackageVersions indicates an expected call of GetPackageVersions.
func (mr *MockGitHubMockRecorder) GetPackageVersions(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPackageVersions", reflect.TypeOf((*MockGitHub)(nil).GetPackageVersions), arg0, arg1, arg2, arg3, arg4)
}

// GetPullRequest mocks base method.
func (m *MockGitHub) GetPullRequest(arg0 context.Context, arg1, arg2 string, arg3 int) (*github.PullRequest, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPullRequest", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(*github.PullRequest)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPullRequest indicates an expected call of GetPullRequest.
func (mr *MockGitHubMockRecorder) GetPullRequest(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPullRequest", reflect.TypeOf((*MockGitHub)(nil).GetPullRequest), arg0, arg1, arg2, arg3)
}

// GetRepository mocks base method.
func (m *MockGitHub) GetRepository(arg0 context.Context, arg1, arg2 string) (*github.Repository, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRepository", arg0, arg1, arg2)
	ret0, _ := ret[0].(*github.Repository)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRepository indicates an expected call of GetRepository.
func (mr *MockGitHubMockRecorder) GetRepository(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRepository", reflect.TypeOf((*MockGitHub)(nil).GetRepository), arg0, arg1, arg2)
}

// GetToken mocks base method.
func (m *MockGitHub) GetToken() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetToken")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetToken indicates an expected call of GetToken.
func (mr *MockGitHubMockRecorder) GetToken() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetToken", reflect.TypeOf((*MockGitHub)(nil).GetToken))
}

// ListAllPackages mocks base method.
func (m *MockGitHub) ListAllPackages(arg0 context.Context, arg1 bool, arg2, arg3 string, arg4, arg5 int) ([]*github.Package, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListAllPackages", arg0, arg1, arg2, arg3, arg4, arg5)
	ret0, _ := ret[0].([]*github.Package)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListAllPackages indicates an expected call of ListAllPackages.
func (mr *MockGitHubMockRecorder) ListAllPackages(arg0, arg1, arg2, arg3, arg4, arg5 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListAllPackages", reflect.TypeOf((*MockGitHub)(nil).ListAllPackages), arg0, arg1, arg2, arg3, arg4, arg5)
}

// ListAllRepositories mocks base method.
func (m *MockGitHub) ListAllRepositories(arg0 context.Context, arg1 bool, arg2 string) ([]*github.Repository, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListAllRepositories", arg0, arg1, arg2)
	ret0, _ := ret[0].([]*github.Repository)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListAllRepositories indicates an expected call of ListAllRepositories.
func (mr *MockGitHubMockRecorder) ListAllRepositories(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListAllRepositories", reflect.TypeOf((*MockGitHub)(nil).ListAllRepositories), arg0, arg1, arg2)
}

// ListEmails mocks base method.
func (m *MockGitHub) ListEmails(ctx context.Context, opts *github.ListOptions) ([]*github.UserEmail, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListEmails", ctx, opts)
	ret0, _ := ret[0].([]*github.UserEmail)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListEmails indicates an expected call of ListEmails.
func (mr *MockGitHubMockRecorder) ListEmails(ctx, opts interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListEmails", reflect.TypeOf((*MockGitHub)(nil).ListEmails), ctx, opts)
}

// ListFiles mocks base method.
func (m *MockGitHub) ListFiles(ctx context.Context, owner, repo string, prNumber, perPage, pageNumber int) ([]*github.CommitFile, *github.Response, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListFiles", ctx, owner, repo, prNumber, perPage, pageNumber)
	ret0, _ := ret[0].([]*github.CommitFile)
	ret1, _ := ret[1].(*github.Response)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ListFiles indicates an expected call of ListFiles.
func (mr *MockGitHubMockRecorder) ListFiles(ctx, owner, repo, prNumber, perPage, pageNumber interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListFiles", reflect.TypeOf((*MockGitHub)(nil).ListFiles), ctx, owner, repo, prNumber, perPage, pageNumber)
}

// ListHooks mocks base method.
func (m *MockGitHub) ListHooks(ctx context.Context, owner, repo string) ([]*github.Hook, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListHooks", ctx, owner, repo)
	ret0, _ := ret[0].([]*github.Hook)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListHooks indicates an expected call of ListHooks.
func (mr *MockGitHubMockRecorder) ListHooks(ctx, owner, repo interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListHooks", reflect.TypeOf((*MockGitHub)(nil).ListHooks), ctx, owner, repo)
}

// ListOrganizationRepsitories mocks base method.
func (m *MockGitHub) ListOrganizationRepsitories(arg0 context.Context, arg1 string) ([]*v1.Repository, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListOrganizationRepsitories", arg0, arg1)
	ret0, _ := ret[0].([]*v1.Repository)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListOrganizationRepsitories indicates an expected call of ListOrganizationRepsitories.
func (mr *MockGitHubMockRecorder) ListOrganizationRepsitories(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListOrganizationRepsitories", reflect.TypeOf((*MockGitHub)(nil).ListOrganizationRepsitories), arg0, arg1)
}

// ListPackagesByRepository mocks base method.
func (m *MockGitHub) ListPackagesByRepository(arg0 context.Context, arg1 bool, arg2, arg3 string, arg4 int64, arg5, arg6 int) ([]*github.Package, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListPackagesByRepository", arg0, arg1, arg2, arg3, arg4, arg5, arg6)
	ret0, _ := ret[0].([]*github.Package)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListPackagesByRepository indicates an expected call of ListPackagesByRepository.
func (mr *MockGitHubMockRecorder) ListPackagesByRepository(arg0, arg1, arg2, arg3, arg4, arg5, arg6 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListPackagesByRepository", reflect.TypeOf((*MockGitHub)(nil).ListPackagesByRepository), arg0, arg1, arg2, arg3, arg4, arg5, arg6)
}

// ListPullRequests mocks base method.
func (m *MockGitHub) ListPullRequests(ctx context.Context, owner, repo string, opt *github.PullRequestListOptions) ([]*github.PullRequest, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListPullRequests", ctx, owner, repo, opt)
	ret0, _ := ret[0].([]*github.PullRequest)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListPullRequests indicates an expected call of ListPullRequests.
func (mr *MockGitHubMockRecorder) ListPullRequests(ctx, owner, repo, opt interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListPullRequests", reflect.TypeOf((*MockGitHub)(nil).ListPullRequests), ctx, owner, repo, opt)
}

// ListReviews mocks base method.
func (m *MockGitHub) ListReviews(arg0 context.Context, arg1, arg2 string, arg3 int, arg4 *github.ListOptions) ([]*github.PullRequestReview, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListReviews", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].([]*github.PullRequestReview)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListReviews indicates an expected call of ListReviews.
func (mr *MockGitHubMockRecorder) ListReviews(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListReviews", reflect.TypeOf((*MockGitHub)(nil).ListReviews), arg0, arg1, arg2, arg3, arg4)
}

// ListUserRepositories mocks base method.
func (m *MockGitHub) ListUserRepositories(arg0 context.Context, arg1 string) ([]*v1.Repository, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListUserRepositories", arg0, arg1)
	ret0, _ := ret[0].([]*v1.Repository)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListUserRepositories indicates an expected call of ListUserRepositories.
func (mr *MockGitHubMockRecorder) ListUserRepositories(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListUserRepositories", reflect.TypeOf((*MockGitHub)(nil).ListUserRepositories), arg0, arg1)
}

// NewRequest mocks base method.
func (m *MockGitHub) NewRequest(method, url string, body any) (*http.Request, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewRequest", method, url, body)
	ret0, _ := ret[0].(*http.Request)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewRequest indicates an expected call of NewRequest.
func (mr *MockGitHubMockRecorder) NewRequest(method, url, body interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewRequest", reflect.TypeOf((*MockGitHub)(nil).NewRequest), method, url, body)
}

// SetCommitStatus mocks base method.
func (m *MockGitHub) SetCommitStatus(arg0 context.Context, arg1, arg2, arg3 string, arg4 *github.RepoStatus) (*github.RepoStatus, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetCommitStatus", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(*github.RepoStatus)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SetCommitStatus indicates an expected call of SetCommitStatus.
func (mr *MockGitHubMockRecorder) SetCommitStatus(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetCommitStatus", reflect.TypeOf((*MockGitHub)(nil).SetCommitStatus), arg0, arg1, arg2, arg3, arg4)
}

// UpdateBranchProtection mocks base method.
func (m *MockGitHub) UpdateBranchProtection(arg0 context.Context, arg1, arg2, arg3 string, arg4 *github.ProtectionRequest) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateBranchProtection", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateBranchProtection indicates an expected call of UpdateBranchProtection.
func (mr *MockGitHubMockRecorder) UpdateBranchProtection(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateBranchProtection", reflect.TypeOf((*MockGitHub)(nil).UpdateBranchProtection), arg0, arg1, arg2, arg3, arg4)
}

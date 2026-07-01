// Package cmd implements the worker command for the Kubernetes Job
// that processes GitHub Action logs and source releases to create releases and SBOMs.
package cmd

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	enry "github.com/go-enry/go-enry/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v69/github"

	// OCI and Container Registry logic
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	// ArangoDB v2 Driver
	"github.com/arangodb/go-driver/v2/arangodb"

	// Import shared packages from the backend
	"github.com/ortelius/ortelius/v12/database"
	"github.com/ortelius/ortelius/v12/model"
	"github.com/ortelius/ortelius/v12/restapi/modules/lifecycle"
	"github.com/ortelius/ortelius/v12/util"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"

	// Import SQLite driver for Syft's RPM database scanning if needed
	_ "github.com/glebarez/go-sqlite"
)

var (
	serverURL string
	verbose   bool

	// Global App Credentials (Required for generating installation tokens)
	envAppID      = os.Getenv("GITHUB_APP_ID")
	envPrivateKey = os.Getenv("GITHUB_PRIVATE_KEY")
)

// -------------------- DATA STRUCTURES --------------------

// GitDetails represents metadata extracted from OCI image labels
type GitDetails struct {
	Authors  string `json:"authors,omitempty"`
	Licenses string `json:"licenses,omitempty"`
	RefName  string `json:"ref_name,omitempty"`
	Revision string `json:"revision,omitempty"`
	Source   string `json:"source,omitempty"`
	Title    string `json:"title,omitempty"`
	URL      string `json:"url,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Version  string `json:"version,omitempty"`
}

// RepoInfo is a provider-agnostic representation of a repository to scan.
type RepoInfo struct {
	Provider string // "github" | "gitlab"
	Owner    string // github org/user or gitlab group
	Name     string
	Private  bool
	Token    string // resolved at scan time via getTokenForRepo
}

// GitScanMetadata contains release/source metadata collected from the checked-out Git repository.
type GitScanMetadata struct {
	CommitTimestamp      string
	CommitAuthors        string
	CommittersCount      string
	TotalCommittersCount string
	ContribPercentage    string
	LinesAdded           string
	LinesDeleted         string
	LinesTotal           string
	PrevComponentCommit  string
	CommitVerified       string
	SignedOffBy          string
}

// -------------------- CLI COMMANDS --------------------

var rootCmd = &cobra.Command{
	Use:   "relscanner",
	Short: "Worker for processing GitHub Action workflows and source releases via ArangoDB discovery",
}

var workflowCmd = &cobra.Command{
	Use:   "process-workflow",
	Short: "Scan all users in ArangoDB and process GitHub Action logs plus source releases",
	RunE:  runScanner,
}

func init() {
	rootCmd.AddCommand(workflowCmd)
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// -------------------- STATE MANAGEMENT --------------------

type ReleaseScanState struct {
	LastReleaseID   int64  `json:"last_release_id"`
	LastPublishedAt string `json:"last_published_at,omitempty"`
	LastTag         string `json:"last_tag,omitempty"`
	LastVersion     string `json:"last_version,omitempty"`
	LastScannedAt   string `json:"last_scanned_at,omitempty"`
}

type ScannerState struct {
	Key               string                      `json:"_key,omitempty"`
	ProcessedRepos    map[string]int64            `json:"processed_repos"`
	ProcessedReleases map[string]ReleaseScanState `json:"processed_releases"`
	LastScannedAt     string                      `json:"last_scanned_at,omitempty"`

	// VisitedThisRun is not persisted — used to deduplicate repos that appear
	// in both org tracked_repos (Pass 2) and system_tracked_repos (Pass 3).
	VisitedThisRun map[string]bool `json:"-"`
}

func newScannerState() *ScannerState {
	return &ScannerState{
		Key:               "relscanner_state",
		ProcessedRepos:    make(map[string]int64),
		ProcessedReleases: make(map[string]ReleaseScanState),
	}
}

func loadScannerState(ctx context.Context, dbConn *database.DBConnection) (*ScannerState, error) {
	query := `RETURN DOCUMENT("metadata/relscanner_state")`
	cursor, err := dbConn.Database.Query(ctx, query, nil)
	if err != nil {
		log.Printf("      ⚠️  Could not load state (first run?): %v", err)
		return newScannerState(), nil
	}
	defer cursor.Close()

	if cursor.HasMore() {
		var state ScannerState
		if _, err := cursor.ReadDocument(ctx, &state); err != nil {
			return newScannerState(), nil
		}
		if state.ProcessedRepos == nil {
			state.ProcessedRepos = make(map[string]int64)
		}
		if state.ProcessedReleases == nil {
			state.ProcessedReleases = make(map[string]ReleaseScanState)
		}
		return &state, nil
	}
	return newScannerState(), nil
}

func saveScannerState(ctx context.Context, dbConn *database.DBConnection, state *ScannerState) error {
	if state == nil {
		state = newScannerState()
	}
	if state.ProcessedRepos == nil {
		state.ProcessedRepos = make(map[string]int64)
	}
	if state.ProcessedReleases == nil {
		state.ProcessedReleases = make(map[string]ReleaseScanState)
	}

	query := `
		UPSERT { _key: "relscanner_state" }
		INSERT {
			_key: "relscanner_state",
			processed_repos: @processedRepos,
			processed_releases: @processedReleases,
			last_scanned_at: DATE_ISO8601(DATE_NOW())
		}
		UPDATE {
			processed_repos: @processedRepos,
			processed_releases: @processedReleases,
			last_scanned_at: DATE_ISO8601(DATE_NOW())
		}
		IN metadata
	`
	bindVars := map[string]interface{}{
		"processedRepos":    state.ProcessedRepos,
		"processedReleases": state.ProcessedReleases,
	}
	_, err := dbConn.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: bindVars})
	return err
}

// -------------------- WORKER LOGIC --------------------

func runScanner(_ *cobra.Command, _ []string) error {
	serverURL = os.Getenv("API_BASE_URL")
	if serverURL == "" {
		serverURL = "http://localhost:3000"
	}

	githubAppConfigured := envAppID != "" && envPrivateKey != ""
	if !githubAppConfigured {
		log.Printf("⚠️  GITHUB_APP_ID or GITHUB_PRIVATE_KEY not set; skipping GitHub App installation discovery and using tracked repos only")
	}

	log.Println("Connecting to ArangoDB...")
	dbConn := database.InitializeDatabase()
	if dbConn.Database == nil {
		return fmt.Errorf("failed to connect to ArangoDB")
	}

	ctx := context.Background()
	state, err := loadScannerState(ctx, &dbConn)
	if err != nil {
		state = newScannerState()
	}

	// ----------------------------------------------------------------
	// Pass 1: Process repos from GitHub App installations (existing flow)
	// ----------------------------------------------------------------
	userQuery := `
		FOR u IN users
		FILTER u.github_installation_id != null AND u.github_installation_id != ""
		RETURN u
	`
	if githubAppConfigured {
		userCursor, err := dbConn.Database.Query(ctx, userQuery, nil)
		if err != nil {
			return fmt.Errorf("user query failed: %w", err)
		}
		defer userCursor.Close()

		for userCursor.HasMore() {
			var user model.User
			if _, err := userCursor.ReadDocument(ctx, &user); err == nil {
				processUserInstallation(ctx, user.GitHubInstallationID, user.Username, state)
			}
		}
	}

	// ----------------------------------------------------------------
	// Pass 2: Process tracked_repos from org documents
	// Each repo is deduplicated by processedRepos — scanned at most once
	// per run regardless of how many orgs track it.
	// ----------------------------------------------------------------
	orgQuery := `
		FOR o IN orgs
		FILTER LENGTH(o.tracked_repos) > 0
		RETURN o
	`
	orgCursor, err := dbConn.Database.Query(ctx, orgQuery, nil)
	if err != nil {
		log.Printf("⚠️  org query failed: %v", err)
	} else {
		defer orgCursor.Close()
		for orgCursor.HasMore() {
			var org model.Org
			if _, err := orgCursor.ReadDocument(ctx, &org); err != nil {
				continue
			}
			for _, trackedRepo := range org.TrackedRepos {
				token, err := getTokenForRepo(trackedRepo, org)
				if err != nil {
					log.Printf("⚠️  skipping %s/%s/%s: %v", trackedRepo.Provider, trackedRepo.Owner, trackedRepo.Name, err)
					continue
				}

				switch trackedRepo.Provider {
				case "github":
					if err := processTrackedGitHubRepo(ctx, token, trackedRepo.Owner, trackedRepo.Name, !trackedRepo.Private, state); err != nil {
						log.Printf("⚠️  error processing %s/%s: %v", trackedRepo.Owner, trackedRepo.Name, err)
					}
				case "gitlab":
					if err := processGitLabRepo(token, trackedRepo.Owner, trackedRepo.Name, !trackedRepo.Private, state.ProcessedRepos); err != nil {
						log.Printf("⚠️  error processing gitlab %s/%s: %v", trackedRepo.Owner, trackedRepo.Name, err)
					}
				default:
					log.Printf("⚠️  unknown provider %q for %s/%s", trackedRepo.Provider, trackedRepo.Owner, trackedRepo.Name)
				}
			}
		}
	}

	// ----------------------------------------------------------------
	// Pass 3: Process system_tracked_repos (public repos tracked via UI)
	// These are provider-agnostic and always public — no org credential needed.
	// Deduplicated by the same processedRepos map as Passes 1 & 2.
	// ----------------------------------------------------------------
	systemRepoQuery := `FOR r IN system_tracked_repos RETURN r`
	systemCursor, err := dbConn.Database.Query(ctx, systemRepoQuery, nil)
	if err != nil {
		log.Printf("⚠️  system_tracked_repos query failed: %v", err)
	} else {
		defer systemCursor.Close()
		for systemCursor.HasMore() {
			var repo model.SystemTrackedRepo
			if _, err := systemCursor.ReadDocument(ctx, &repo); err != nil {
				continue
			}

			token := os.Getenv("GITHUB_TOKEN")
			if repo.Provider == "gitlab" {
				token = os.Getenv("GITLAB_TOKEN")
			}

			log.Printf("   🌐 [Pass 3] Processing public repo %s/%s/%s", repo.Provider, repo.Owner, repo.Name)

			switch repo.Provider {
			case "github":
				if err := processTrackedGitHubRepo(ctx, token, repo.Owner, repo.Name, true, state); err != nil {
					log.Printf("      ⚠️  error processing public github %s/%s: %v", repo.Owner, repo.Name, err)
				}
			case "gitlab":
				if err := processGitLabRepo(token, repo.Owner, repo.Name, true, state.ProcessedRepos); err != nil {
					log.Printf("      ⚠️  error processing public gitlab %s/%s: %v", repo.Owner, repo.Name, err)
				}
			default:
				log.Printf("      ⚠️  unknown provider %q for system repo %s/%s", repo.Provider, repo.Owner, repo.Name)
			}
		}
	}

	saveScannerState(ctx, &dbConn, state)

	// ----------------------------------------------------------------
	// Pass 4: Seed cve_lifecycle sentinel records for ALL release versions
	// (not just is_latest) so the trend chart has full historical data.
	// After seeding, IngestAllUndeployedReleases calls
	// ReconcileSentinelRemediations internally for every release touched,
	// marking CVEs as remediated when they drop out of a newer version.
	//
	// Must run AFTER the release scan passes so release2cve edges are
	// fully populated. Safe to re-run — idempotent guard on sentinel records.
	// ----------------------------------------------------------------
	log.Println("🔍 [Pass 4] Seeding release-based lifecycle records for all versions...")
	if err := lifecycle.IngestAllUndeployedReleases(ctx, &dbConn, ""); err != nil {
		log.Printf("⚠️  release lifecycle seeding failed: %v", err)
	} else {
		log.Println("✅ [Pass 4] Release lifecycle seeding and remediation reconcile complete")
	}

	return nil
}

// getTokenForRepo resolves the correct token for a tracked repo.
//
// Priority:
//  1. GitHub App installation token (preferred — covers private + public)
//  2. Org GitHub PAT (fallback for private GitHub repos without app)
//  3. Org GitLab PAT (required for all GitLab repos)
//  4. System GITHUB_TOKEN (public repos only, for rate limit purposes)
func getTokenForRepo(repo model.TrackedRepo, org model.Org) (string, error) {
	switch repo.Provider {
	case "github":
		if !repo.Private {
			token := os.Getenv("GITHUB_TOKEN")
			if token == "" {
				log.Printf("⚠️  GITHUB_TOKEN is empty; using unauthenticated GitHub API for public repo %s/%s", repo.Owner, repo.Name)
			}
			return token, nil
		}

		if org.GitHubInstallationID != "" && envAppID != "" && envPrivateKey != "" {
			token, err := getInstallationToken(envAppID, envPrivateKey, org.GitHubInstallationID)
			if err == nil {
				return token, nil
			}
			log.Printf("⚠️  failed to get GitHub App installation token for %s/%s: %v", repo.Owner, repo.Name, err)
		}

		if org.GitHubTokenEnc != "" {
			token, err := util.DecryptToken(org.GitHubTokenEnc)
			if err != nil {
				return "", fmt.Errorf("failed to decrypt github token for org %s: %w", org.Name, err)
			}
			return token, nil
		}

		return "", fmt.Errorf("no credentials available for private GitHub repo %s/%s", repo.Owner, repo.Name)

	case "gitlab":
		if org.GitLabTokenEnc != "" {
			token, err := util.DecryptToken(org.GitLabTokenEnc)
			if err != nil {
				return "", fmt.Errorf("failed to decrypt gitlab token for org %s: %w", org.Name, err)
			}
			return token, nil
		}
		if repo.Private {
			return "", fmt.Errorf("no credentials available for private GitLab repo %s/%s", repo.Owner, repo.Name)
		}
		return "", nil

	default:
		return "", fmt.Errorf("unsupported repo provider %q for %s/%s", repo.Provider, repo.Owner, repo.Name)
	}
}

func newGitHubClient(ctx context.Context, token string) *github.Client {
	if token == "" {
		return github.NewClient(nil)
	}
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc)
}

// processTrackedGitHubRepo processes a single GitHub repo from an org's tracked_repos list.
func processTrackedGitHubRepo(ctx context.Context, token, owner, repoName string, isPublic bool, state *ScannerState) error {
	repoKey := fmt.Sprintf("github/%s/%s", owner, repoName)

	if state.VisitedThisRun == nil {
		state.VisitedThisRun = make(map[string]bool)
	}
	if state.VisitedThisRun[repoKey] {
		log.Printf("      ⏭️  %s already processed this run, skipping", repoKey)
		return nil
	}
	state.VisitedThisRun[repoKey] = true

	client := newGitHubClient(ctx, token)

	repo, _, err := client.Repositories.Get(ctx, owner, repoName)
	if err != nil {
		return fmt.Errorf("failed to get repo %s: %w", repoKey, err)
	}
	if repo.GetArchived() {
		log.Printf("      ⏭️  Skipping archived repo: %s", repoKey)
		return nil
	}

	if err := processSingleRepo(ctx, client, token, owner, repoName, isPublic, state.ProcessedRepos); err != nil {
		log.Printf("      ⚠️  workflow scan skipped for %s/%s: %v", owner, repoName, err)
	}

	return processGitHubSourceReleases(ctx, client, token, owner, repoName, isPublic, state)
}

func processUserInstallation(ctx context.Context, installationID, _ string, state *ScannerState) error {
	token, err := getInstallationToken(envAppID, envPrivateKey, installationID)
	if err != nil {
		return err
	}

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	opt := &github.ListOptions{PerPage: 100}
	for {
		repos, resp, err := client.Apps.ListRepos(ctx, opt)
		if err != nil {
			break
		}
		for _, repo := range repos.Repositories {
			if !repo.GetArchived() {
				if err := processSingleRepo(ctx, client, token, repo.GetOwner().GetLogin(), repo.GetName(), !repo.GetPrivate(), state.ProcessedRepos); err != nil {
					log.Printf("      ⚠️  workflow scan skipped for %s/%s: %v", repo.GetOwner().GetLogin(), repo.GetName(), err)
				}
				if err := processGitHubSourceReleases(ctx, client, token, repo.GetOwner().GetLogin(), repo.GetName(), !repo.GetPrivate(), state); err != nil {
					log.Printf("      ⚠️  source-release scan skipped for %s/%s: %v", repo.GetOwner().GetLogin(), repo.GetName(), err)
				}
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return nil
}

func processSingleRepo(ctx context.Context, client *github.Client, token, owner, repoName string, isPublic bool, processedRepos map[string]int64) error {
	repoKey := fmt.Sprintf("github/%s/%s", owner, repoName)
	lastProcessedID := processedRepos[repoKey]

	targets, highestSeenID, err := findLatestRelevantRuns(ctx, client, owner, repoName, 5, lastProcessedID)

	if err != nil {
		if highestSeenID > processedRepos[repoKey] {
			processedRepos[repoKey] = highestSeenID
			log.Printf("      ⏭️  No actionable runs for %s/%s; checkpointing at run %d", owner, repoName, highestSeenID)
		}
		return err
	}

	var lastErr error
	processedAny := false

	for _, target := range targets {
		if lastID, exists := processedRepos[repoKey]; exists && target.RunID <= lastID {
			log.Printf("      ⏭️  workflow run %s/%s %d already processed", owner, repoName, target.RunID)
			continue
		}

		if err := processWorkflowScanTarget(ctx, client, token, owner, repoName, isPublic, processedRepos, target); err != nil {
			lastErr = err
			log.Printf("      ⚠️  workflow run %s/%s %d failed: %v", owner, repoName, target.RunID, err)
			continue
		}

		processedAny = true
	}

	if !processedAny && lastErr != nil {
		return lastErr
	}

	return nil
}

func processWorkflowScanTarget(
	ctx context.Context,
	client *github.Client,
	token string,
	owner string,
	repoName string,
	isPublic bool,
	processedRepos map[string]int64,
	target WorkflowScanTarget,
) error {
	runID := target.RunID
	commitSHA := target.CommitSHA
	branchName := target.Branch
	analysis := target.Analysis

	if analysis == nil {
		return fmt.Errorf("workflow run %d has no analysis", runID)
	}

	repoKey := fmt.Sprintf("github/%s/%s", owner, repoName)

	var gitDetails *GitDetails
	if analysis.DockerImage != "" {
		gitDetails, _ = extractImageLabels(analysis.DockerImage)
	}

	releaseVersion := "0.0.0-snapshot"
	if analysis.DockerImage != "" {
		parts := strings.Split(analysis.DockerImage, ":")
		if len(parts) > 1 {
			releaseVersion = parts[len(parts)-1]
		}
	} else if analysis.ReleaseVersion != "" {
		releaseVersion = analysis.ReleaseVersion
	}

	tempDir, _ := os.MkdirTemp("", "relscanner-*")
	defer func() {
		os.RemoveAll(tempDir)
		cleanStereoscopeTemps()
	}()

	cloneURL := githubCloneURL(token, owner, repoName)
	if err := gitCloneCheckout(cloneURL, commitSHA, tempDir); err != nil {
		return err
	}

	originalWd, _ := os.Getwd()
	os.Chdir(tempDir)
	defer os.Chdir(originalWd)

	mapping := util.GetDerivedEnvMapping(make(map[string]string))
	mapping["CompName"] = fmt.Sprintf("%s/%s", owner, repoName)
	mapping["GitRepoProject"] = repoName
	mapping["GitRepo"] = repoName
	mapping["GitOrg"] = owner
	mapping["GitCommit"] = commitSHA
	mapping["GitBranch"] = branchName
	mapping["BuildId"] = fmt.Sprintf("%d", runID)
	mapping["GitUrl"] = fmt.Sprintf("https://github.com/%s/%s", owner, repoName)

	if gitDetails != nil {
		if gitDetails.URL != "" {
			mapping["GitUrl"] = gitDetails.URL
		}
		if gitDetails.Revision != "" {
			mapping["GitCommit"] = gitDetails.Revision
		}
		if gitDetails.Authors != "" {
			mapping["GitCommitAuthors"] = gitDetails.Authors
		}
	}

	if analysis.DockerImage != "" {
		mapping["DockerRepo"] = analysis.DockerImage
		mapping["DockerTag"] = releaseVersion
		mapping["DockerSha"] = resolveDockerImageDigest(analysis.DockerImage)
		mapping["DockerBasename"] = dockerImageBasename(analysis.DockerImage)
		mapping["ProjectType"] = "container"
	} else {
		mapping["GitTag"] = releaseVersion
		mapping["ProjectType"] = "application"
	}

	if commitForMetadata := mapping["GitCommit"]; commitForMetadata != "" {
		gitMeta := collectGitScanMetadata(tempDir, commitForMetadata)
		applyGitScanMetadata(mapping, gitMeta)
	}

	release := buildRelease(mapping, mapping["ProjectType"], isPublic)
	populateContentSha(release)

	var sbomBytes []byte
	var dockerSHA string

	if analysis.DockerImage != "" {
		log.Printf("      🔍 Checking OCI Referrers for SBOM: %s", analysis.DockerImage)
		extractedSbom, err := extractSBOMFromImage(analysis.DockerImage)
		if err == nil {
			sbomBytes = extractedSbom
			log.Printf("      ✅ Extracted SBOM from OCI Attestation")
		}
	}

	if len(sbomBytes) == 0 && analysis.HasSBOM {
		downloaded, err := downloadSBOMArtifact(ctx, client, owner, repoName, runID)
		if err == nil {
			sbomBytes = downloaded
		}
	}

	if len(sbomBytes) == 0 && analysis.DockerImage != "" {
		sbomBytes, dockerSHA, _ = generateSBOMFromInput(ctx, analysis.DockerImage)
	}

	if len(sbomBytes) == 0 && isCCppRepo(tempDir) {
		generated, err := generateCdxgenSBOM(tempDir)
		if err == nil {
			cleaned, cleanErr := cleanupCycloneDXMainComponent(generated, owner, repoName, releaseVersion)
			if cleanErr == nil {
				sbomBytes = cleaned
			} else {
				sbomBytes = generated
				log.Printf("      ⚠️  cdxgen SBOM generated but metadata.component cleanup failed: %v", cleanErr)
			}
			log.Printf("      ✅ Generated C/C++ SBOM with cdxgen")
		} else {
			log.Printf("      ⚠️  cdxgen C/C++ SBOM generation failed: %v", err)
		}
	}

	if len(sbomBytes) == 0 {
		sbomBytes = minimalCycloneDXSBOM(owner, repoName, releaseVersion)
	}

	if dockerSHA != "" {
		release.DockerSha = dockerSHA
		release.ContentSha = dockerSHA
	}

	scorecardResult, aggregateScore, err := fetchOpenSSFScorecard(release.GitURL, release.GitCommit)
	if err == nil {
		release.ScorecardResult = scorecardResult
		release.OpenSSFScorecardScore = aggregateScore
	}

	sbomObj := model.NewSBOM()
	sbomObj.Content = json.RawMessage(sbomBytes)
	req := model.ReleaseWithSBOM{ProjectRelease: *release, SBOM: *sbomObj}

	if err := postRelease(serverURL, req); err != nil {
		return err
	}

	processedRepos[repoKey] = runID
	log.Printf("      🚀 Release %s synced (SHA: %s)", releaseVersion, release.ContentSha)

	return nil
}

// -------------------- GITHUB SOURCE RELEASE LOGIC --------------------

func processGitHubSourceReleases(ctx context.Context, client *github.Client, token, owner, repoName string, isPublic bool, state *ScannerState) error {
	const maxSourceReleases = 5

	if state.ProcessedReleases == nil {
		state.ProcessedReleases = make(map[string]ReleaseScanState)
	}

	repoKey := fmt.Sprintf("github/%s/%s", owner, repoName)
	lastState := state.ProcessedReleases[repoKey]
	var pending []*github.RepositoryRelease

	opt := &github.ListOptions{PerPage: maxSourceReleases}
	for len(pending) < maxSourceReleases {
		releases, resp, err := client.Repositories.ListReleases(ctx, owner, repoName, opt)
		if err != nil {
			return fmt.Errorf("failed to list releases for %s/%s: %w", owner, repoName, err)
		}

		for _, ghRelease := range releases {
			if ghRelease.GetDraft() {
				continue
			}
			if ghRelease.GetID() <= lastState.LastReleaseID {
				continue
			}
			if strings.TrimSpace(ghRelease.GetTagName()) == "" {
				continue
			}

			pending = append(pending, ghRelease)
			if len(pending) >= maxSourceReleases {
				break
			}
		}

		if resp == nil || resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	sort.Slice(pending, func(i, j int) bool { return pending[i].GetID() < pending[j].GetID() })

	for _, ghRelease := range pending {
		if err := processGitHubSourceRelease(ctx, client, token, owner, repoName, ghRelease, isPublic); err != nil {
			log.Printf("      ⚠️  source release %s/%s %s failed: %v", owner, repoName, ghRelease.GetTagName(), err)
			continue
		}

		version := releaseVersionFromGitHubRelease(owner, repoName, ghRelease)
		state.ProcessedReleases[repoKey] = ReleaseScanState{
			LastReleaseID:   ghRelease.GetID(),
			LastPublishedAt: githubTimestampToString(ghRelease.GetPublishedAt()),
			LastTag:         ghRelease.GetTagName(),
			LastVersion:     version,
			LastScannedAt:   time.Now().UTC().Format(time.RFC3339),
		}
	}

	return nil
}

func processGitHubSourceRelease(ctx context.Context, client *github.Client, token, owner, repoName string, ghRelease *github.RepositoryRelease, isPublic bool) error {
	tagName := ghRelease.GetTagName()
	version := releaseVersionFromGitHubRelease(owner, repoName, ghRelease)
	if version == "" {
		version = tagName
	}

	var sbomBytes []byte
	var commitSHA string
	var tempDir string

	cleanupTemp := func() {
		if tempDir != "" {
			os.RemoveAll(tempDir)
		}
		cleanStereoscopeTemps()
	}
	defer cleanupTemp()

	ensureTempDir := func(prefix string) (string, error) {
		if tempDir != "" {
			return tempDir, nil
		}
		dir, err := os.MkdirTemp("", prefix)
		if err != nil {
			return "", err
		}
		tempDir = dir
		return tempDir, nil
	}

	ensureCheckout := func() error {
		if tempDir != "" {
			if _, err := os.Stat(filepath.Join(tempDir, ".git")); err == nil {
				return nil
			}
			os.RemoveAll(tempDir)
			tempDir = ""
		}

		dir, err := ensureTempDir("relscanner-release-*")
		if err != nil {
			return err
		}

		cloneURL := githubCloneURL(token, owner, repoName)
		if err := gitCloneCheckoutRef(cloneURL, tagName, dir); err != nil {
			return fmt.Errorf("failed to clone checkout tag %s: %w", tagName, err)
		}

		resolved, err := gitResolveHead(dir)
		if err != nil {
			return fmt.Errorf("failed to resolve release commit for tag %s: %w", tagName, err)
		}
		commitSHA = resolved
		return nil
	}

	resolveCommitViaAPI := func() {
		if commitSHA != "" {
			return
		}
		if resolved, err := resolveGitHubReleaseCommit(ctx, client, owner, repoName, tagName); err == nil {
			commitSHA = resolved
		} else {
			log.Printf("      ⚠️  Failed to resolve release tag %s via GitHub API: %v", tagName, err)
		}
	}

	if downloaded, err := downloadGitHubReleaseSBOMAsset(ctx, client, owner, repoName, ghRelease.GetID()); err == nil && len(downloaded) > 0 {
		if cleaned, cleanErr := cleanupCycloneDXMainComponent(downloaded, owner, repoName, version); cleanErr == nil {
			sbomBytes = cleaned
		} else {
			sbomBytes = downloaded
			log.Printf("      ⚠️  release SBOM asset found but CycloneDX metadata.component cleanup failed: %v", cleanErr)
		}
		log.Printf("      ✅ Found SBOM release asset for %s/%s %s", owner, repoName, tagName)
		resolveCommitViaAPI()
	} else if err != nil {
		log.Printf("      ℹ️  No SBOM release asset for %s/%s %s: %v", owner, repoName, tagName, err)
	}

	if len(sbomBytes) == 0 {
		assetPath, assetName, err := downloadGitHubReleaseJavaArtifactAsset(ctx, client, owner, repoName, ghRelease.GetID(), ensureTempDir)
		if err == nil && assetPath != "" {
			generated, _, genErr := generateSBOMFromInput(ctx, assetPath)
			if genErr != nil {
				log.Printf("      ⚠️  Syft Java artifact SBOM generation failed for %s/%s %s asset %s: %v", owner, repoName, tagName, assetName, genErr)
			} else if cleaned, cleanErr := cleanupCycloneDXMainComponent(generated, owner, repoName, version); cleanErr != nil {
				log.Printf("      ⚠️  Java artifact SBOM generated but metadata.component cleanup failed: %v", cleanErr)
				sbomBytes = generated
			} else {
				sbomBytes = cleaned
				log.Printf("      ✅ Generated Java artifact SBOM with Syft for %s/%s %s from %s", owner, repoName, tagName, assetName)
			}
			resolveCommitViaAPI()
		} else if err != nil {
			log.Printf("      ℹ️  No Java release artifact for %s/%s %s: %v", owner, repoName, tagName, err)
		}
	}

	if len(sbomBytes) == 0 {
		if err := ensureCheckout(); err != nil {
			return err
		}

		if isCCppRepo(tempDir) {
			generated, err := generateCdxgenSBOM(tempDir)
			if err != nil {
				log.Printf("      ⚠️  cdxgen C/C++ SBOM generation failed for %s/%s %s: %v", owner, repoName, tagName, err)
			} else if cleaned, cleanErr := cleanupCycloneDXMainComponent(generated, owner, repoName, version); cleanErr != nil {
				log.Printf("      ⚠️  cdxgen SBOM generated but metadata.component cleanup failed: %v", cleanErr)
				sbomBytes = generated
			} else {
				sbomBytes = cleaned
				log.Printf("      ✅ Generated C/C++ SBOM with cdxgen for %s/%s %s", owner, repoName, tagName)
			}
		} else {
			generated, _, err := generateSBOMFromInput(ctx, tempDir)
			if err != nil {
				log.Printf("      ⚠️  Syft source SBOM generation failed for %s/%s %s: %v", owner, repoName, tagName, err)
			} else if cleaned, cleanErr := cleanupCycloneDXMainComponent(generated, owner, repoName, version); cleanErr != nil {
				log.Printf("      ⚠️  Syft SBOM generated but metadata.component cleanup failed: %v", cleanErr)
				sbomBytes = generated
			} else {
				sbomBytes = cleaned
				log.Printf("      ✅ Generated source SBOM with Syft for %s/%s %s", owner, repoName, tagName)
			}
		}
	}

	if err := ensureCheckout(); err != nil {
		return err
	}

	if len(sbomBytes) == 0 {
		sbomBytes = minimalCycloneDXSBOM(owner, repoName, version)
	}

	mapping := util.GetDerivedEnvMapping(make(map[string]string))
	mapping["CompName"] = fmt.Sprintf("%s/%s", owner, repoName)
	mapping["GitRepoProject"] = repoName
	mapping["GitRepo"] = repoName
	mapping["GitOrg"] = owner
	mapping["GitCommit"] = commitSHA
	mapping["GitBranch"] = ghRelease.GetTargetCommitish()
	mapping["GitTag"] = tagName
	mapping["GitVersion"] = version
	mapping["BuildId"] = fmt.Sprintf("%d", ghRelease.GetID())
	mapping["BuildNumber"] = fmt.Sprintf("%d", ghRelease.GetID())
	mapping["BuildUrl"] = ghRelease.GetHTMLURL()
	mapping["BuildDate"] = githubTimestampToString(ghRelease.GetPublishedAt())
	mapping["GitUrl"] = fmt.Sprintf("https://github.com/%s/%s", owner, repoName)
	mapping["ProjectType"] = "application"

	if commitSHA != "" {
		gitMeta := collectGitScanMetadata(tempDir, commitSHA)
		applyGitScanMetadata(mapping, gitMeta)
	}

	release := buildRelease(mapping, "application", isPublic)
	populateContentSha(release)

	scorecardResult, aggregateScore, err := fetchOpenSSFScorecard(release.GitURL, release.GitCommit)
	if err == nil {
		release.ScorecardResult = scorecardResult
		release.OpenSSFScorecardScore = aggregateScore
	}

	sbomObj := model.NewSBOM()
	sbomObj.Content = json.RawMessage(sbomBytes)
	req := model.ReleaseWithSBOM{ProjectRelease: *release, SBOM: *sbomObj}

	if err := postRelease(serverURL, req); err != nil {
		return err
	}

	log.Printf("      🚀 Source release %s/%s %s synced (SHA: %s)", owner, repoName, version, release.ContentSha)
	return nil
}

func isSBOMReleaseAsset(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}

	hasSBOMName := strings.Contains(n, "sbom") ||
		strings.Contains(n, "cyclonedx") ||
		strings.Contains(n, "cdx") ||
		strings.Contains(n, "spdx")

	hasSBOMExt := strings.HasSuffix(n, ".json") ||
		strings.HasSuffix(n, ".xml") ||
		strings.HasSuffix(n, ".spdx") ||
		strings.HasSuffix(n, ".spdx.json") ||
		strings.HasSuffix(n, ".zip")

	return hasSBOMName && hasSBOMExt
}

func downloadGitHubReleaseSBOMAsset(ctx context.Context, client *github.Client, owner, repoName string, releaseID int64) ([]byte, error) {
	assets, _, err := client.Repositories.ListReleaseAssets(ctx, owner, repoName, releaseID, &github.ListOptions{PerPage: 100})
	if err != nil {
		return nil, err
	}

	for _, asset := range assets {
		name := asset.GetName()
		if !isSBOMReleaseAsset(name) {
			continue
		}

		rc, _, err := client.Repositories.DownloadReleaseAsset(ctx, owner, repoName, asset.GetID(), http.DefaultClient)
		if err != nil {
			return nil, fmt.Errorf("failed to download release asset %s: %w", name, err)
		}
		defer rc.Close()

		content, err := io.ReadAll(rc)
		if err != nil {
			return nil, fmt.Errorf("failed to read release asset %s: %w", name, err)
		}

		if strings.HasSuffix(strings.ToLower(name), ".zip") {
			return unzipFirstJSON(content)
		}
		return content, nil
	}

	return nil, fmt.Errorf("no SBOM release asset found")
}

func isJavaReleaseArtifactAsset(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}

	if strings.Contains(n, "-sources.") ||
		strings.Contains(n, "-javadoc.") ||
		strings.Contains(n, "-tests.") ||
		strings.Contains(n, "-test.") ||
		strings.Contains(n, "source") {
		return false
	}

	return strings.HasSuffix(n, ".war") ||
		strings.HasSuffix(n, ".ear") ||
		strings.HasSuffix(n, ".hpi") ||
		strings.HasSuffix(n, ".jpi") ||
		strings.HasSuffix(n, ".jar")
}

func javaReleaseArtifactRank(name string) int {
	n := strings.ToLower(strings.TrimSpace(name))

	switch {
	case strings.HasSuffix(n, ".war"):
		return 0
	case strings.HasSuffix(n, ".ear"):
		return 1
	case strings.HasSuffix(n, ".hpi") || strings.HasSuffix(n, ".jpi"):
		return 2
	case strings.HasSuffix(n, ".jar"):
		return 3
	default:
		return 99
	}
}

func downloadGitHubReleaseJavaArtifactAsset(
	ctx context.Context,
	client *github.Client,
	owner string,
	repoName string,
	releaseID int64,
	ensureTempDir func(prefix string) (string, error),
) (string, string, error) {
	assets, _, err := client.Repositories.ListReleaseAssets(ctx, owner, repoName, releaseID, &github.ListOptions{PerPage: 100})
	if err != nil {
		return "", "", err
	}

	var candidates []*github.ReleaseAsset
	for _, asset := range assets {
		if isJavaReleaseArtifactAsset(asset.GetName()) {
			candidates = append(candidates, asset)
		}
	}

	if len(candidates) == 0 {
		return "", "", fmt.Errorf("no Java artifact release asset found")
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		ri := javaReleaseArtifactRank(candidates[i].GetName())
		rj := javaReleaseArtifactRank(candidates[j].GetName())
		if ri != rj {
			return ri < rj
		}
		return candidates[i].GetSize() > candidates[j].GetSize()
	})

	asset := candidates[0]
	name := asset.GetName()

	rc, _, err := client.Repositories.DownloadReleaseAsset(ctx, owner, repoName, asset.GetID(), http.DefaultClient)
	if err != nil {
		return "", name, fmt.Errorf("failed to download Java release asset %s: %w", name, err)
	}
	defer rc.Close()

	dir, err := ensureTempDir("relscanner-release-asset-*")
	if err != nil {
		return "", name, err
	}

	assetPath := filepath.Join(dir, filepath.Base(name))
	out, err := os.Create(assetPath)
	if err != nil {
		return "", name, fmt.Errorf("failed to create temp Java release asset %s: %w", name, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, rc); err != nil {
		return "", name, fmt.Errorf("failed to write temp Java release asset %s: %w", name, err)
	}

	return assetPath, name, nil
}

func resolveGitHubReleaseCommit(ctx context.Context, client *github.Client, owner, repoName, tagName string) (string, error) {
	ref, _, err := client.Git.GetRef(ctx, owner, repoName, "tags/"+tagName)
	if err != nil {
		return "", err
	}
	if ref == nil || ref.Object == nil || ref.Object.GetSHA() == "" {
		return "", fmt.Errorf("tag ref %s has no object SHA", tagName)
	}

	if ref.Object.GetType() == "tag" {
		tag, _, err := client.Git.GetTag(ctx, owner, repoName, ref.Object.GetSHA())
		if err != nil {
			return "", err
		}
		if tag == nil || tag.Object == nil || tag.Object.GetSHA() == "" {
			return "", fmt.Errorf("annotated tag %s has no target SHA", tagName)
		}
		return tag.Object.GetSHA(), nil
	}

	return ref.Object.GetSHA(), nil
}

func releaseVersionFromGitHubRelease(owner, repoName string, ghRelease *github.RepositoryRelease) string {
	version := normalizeComponentVersion(owner, repoName, ghRelease.GetTagName())
	if version != "" {
		return version
	}
	return strings.TrimSpace(ghRelease.GetName())
}

func normalizeComponentVersion(owner, repoName, tag string) string {
	v := strings.TrimSpace(tag)
	if v == "" {
		return ""
	}
	v = strings.TrimPrefix(v, "refs/tags/")
	v = strings.TrimPrefix(v, "v")

	if owner == "curl" && repoName == "curl" {
		v = strings.TrimPrefix(v, "curl-")
		v = strings.ReplaceAll(v, "_", ".")
	}

	return v
}

func githubTimestampToString(ts github.Timestamp) string {
	if ts.IsZero() {
		return ""
	}
	return ts.Time.UTC().Format(time.RFC3339)
}

// -------------------- OCI & SBOM LOGIC --------------------

func extractImageLabels(imageRef string) (*GitDetails, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, err
	}
	desc, err := remote.Get(ref)
	if err != nil {
		return nil, err
	}
	img, err := desc.Image()
	if err != nil {
		return nil, err
	}
	configFile, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}

	labels := configFile.Config.Labels
	return &GitDetails{
		Authors:  labels["org.opencontainers.image.authors"],
		Licenses: labels["org.opencontainers.image.licenses"],
		Revision: labels["org.opencontainers.image.revision"],
		Source:   labels["org.opencontainers.image.source"],
		URL:      labels["org.opencontainers.image.url"],
		Version:  labels["org.opencontainers.image.version"],
	}, nil
}

func extractSBOMFromImage(imageRef string) ([]byte, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, err
	}

	if sbom, err := extractSBOMFromOCIReferrers(ref); err == nil {
		return sbom, nil
	}

	desc, err := remote.Get(ref)
	if err != nil {
		return nil, err
	}
	leafRef, _ := name.ParseReference(fmt.Sprintf("%s@%s", ref.Context().Name(), desc.Digest.String()))

	if sbom, err := extractSBOMFromCosignAttestation(leafRef); err == nil {
		return sbom, nil
	}
	return nil, fmt.Errorf("no OCI SBOM found")
}

func extractSBOMFromOCIReferrers(ref name.Reference) ([]byte, error) {
	desc, err := remote.Get(ref)
	if err != nil {
		return nil, err
	}
	idx, err := remote.Referrers(ref.Context().Digest(desc.Digest.String()))
	if err != nil {
		return nil, err
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}

	for _, m := range manifest.Manifests {
		aType := strings.ToLower(m.ArtifactType)
		if aType == "" {
			aType = strings.ToLower(string(m.MediaType))
		}
		if strings.Contains(aType, "sbom") || strings.Contains(aType, "cyclonedx") {
			rDigest, _ := name.NewDigest(fmt.Sprintf("%s@%s", ref.Context().Name(), m.Digest.String()))
			img, err := remote.Image(rDigest)
			if err != nil {
				continue
			}
			layers, _ := img.Layers()
			if len(layers) > 0 {
				rc, _ := layers[0].Uncompressed()
				defer rc.Close()
				return io.ReadAll(rc)
			}
		}
	}
	return nil, fmt.Errorf("not found")
}

func extractSBOMFromCosignAttestation(ref name.Reference) ([]byte, error) {
	desc, err := remote.Get(ref)
	if err != nil {
		return nil, err
	}
	idx, err := remote.Referrers(ref.Context().Digest(desc.Digest.String()))
	if err != nil {
		return nil, err
	}
	manifest, _ := idx.IndexManifest()

	for _, m := range manifest.Manifests {
		if !strings.Contains(string(m.MediaType), "dsse") {
			continue
		}
		rDigest, _ := name.NewDigest(fmt.Sprintf("%s@%s", ref.Context().Name(), m.Digest.String()))
		img, _ := remote.Image(rDigest)
		layers, _ := img.Layers()
		if len(layers) > 0 {
			rc, _ := layers[0].Uncompressed()
			content, _ := io.ReadAll(rc)
			rc.Close()

			var env struct {
				Payload string `json:"payload"`
			}
			if err := json.Unmarshal(content, &env); err == nil {
				data, _ := base64.StdEncoding.DecodeString(env.Payload)
				var statement map[string]interface{}
				if err := json.Unmarshal(data, &statement); err == nil {
					if pred, ok := statement["predicate"]; ok {
						return json.Marshal(pred)
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("not found")
}

func resolveDockerImageDigest(imageRef string) string {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		log.Printf("      ⚠️  failed to parse Docker image reference %s: %v", imageRef, err)
		return ""
	}

	desc, err := remote.Get(ref)
	if err != nil {
		log.Printf("      ⚠️  failed to resolve Docker image digest for %s: %v", imageRef, err)
		return ""
	}

	return desc.Digest.String()
}

func dockerImageBasename(imageRef string) string {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return ""
	}

	repo := ref.Context().RepositoryStr()
	if repo == "" {
		return ""
	}

	parts := strings.Split(repo, "/")
	return parts[len(parts)-1]
}

// -------------------- EXISTING HELPERS --------------------

func isCCppRepo(root string) bool {
	counts := map[string]int{
		"C":           0,
		"C++":         0,
		"Objective-C": 0,
	}
	markerFound := false

	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if shouldSkipRepoDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		base := filepath.Base(path)
		if strings.HasPrefix(base, ".") {
			return nil
		}
		if isCppBuildMarker(base) {
			markerFound = true
		}
		if enry.IsVendor(path) {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil || enry.IsBinary(content) || enry.IsGenerated(path, content) {
			return nil
		}

		lang := enry.GetLanguage(path, content)
		if _, ok := counts[lang]; ok {
			counts[lang]++
		}
		return nil
	})

	cppCount := counts["C"] + counts["C++"] + counts["Objective-C"]
	return cppCount >= 3 || (cppCount > 0 && markerFound)
}

func shouldSkipRepoDir(name string) bool {
	switch strings.ToLower(name) {
	case ".git", "node_modules", "vendor", "dist", "build", "target", ".cache":
		return true
	default:
		return false
	}
}

func isCppBuildMarker(name string) bool {
	switch strings.ToLower(name) {
	case "cmakelists.txt", "configure", "configure.ac", "makefile", "meson.build", "conanfile.txt", "conanfile.py", "vcpkg.json", "compile_commands.json":
		return true
	default:
		return false
	}
}

func generateCdxgenSBOM(repoDir string) ([]byte, error) {
	outFile := filepath.Join(repoDir, "bom.cdx.json")
	cmd := exec.Command("cdxgen", "-t", "cpp", "-o", outFile, "--spec-version", "1.5", repoDir)
	cmd.Dir = repoDir

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("cdxgen failed: %w: %s", err, stderr.String())
	}
	return os.ReadFile(outFile)
}

func cleanupCycloneDXMainComponent(sbomBytes []byte, owner, repoName, componentVersion string) ([]byte, error) {
	var bom map[string]interface{}
	if err := json.Unmarshal(sbomBytes, &bom); err != nil {
		return nil, fmt.Errorf("failed to parse CycloneDX SBOM: %w", err)
	}

	metadata, ok := bom["metadata"].(map[string]interface{})
	if !ok {
		metadata = map[string]interface{}{}
		bom["metadata"] = metadata
	}

	purl := fmt.Sprintf("pkg:github/%s/%s@%s", owner, repoName, componentVersion)

	metadata["component"] = map[string]interface{}{
		"type":    "application",
		"name":    repoName,
		"version": componentVersion,
		"purl":    purl,
		"bom-ref": purl,
		"externalReferences": []map[string]interface{}{
			{
				"type": "vcs",
				"url":  fmt.Sprintf("https://github.com/%s/%s", owner, repoName),
			},
		},
	}

	return json.Marshal(bom)
}

func minimalCycloneDXSBOM(owner, repoName, componentVersion string) []byte {
	purl := fmt.Sprintf("pkg:github/%s/%s@%s", owner, repoName, componentVersion)

	bom := map[string]interface{}{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"metadata": map[string]interface{}{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"component": map[string]interface{}{
				"type":    "application",
				"name":    repoName,
				"version": componentVersion,
				"purl":    purl,
				"bom-ref": purl,
				"externalReferences": []map[string]interface{}{
					{
						"type": "vcs",
						"url":  fmt.Sprintf("https://github.com/%s/%s", owner, repoName),
					},
				},
			},
		},
		"components": []interface{}{},
	}

	out, _ := json.Marshal(bom)
	return out
}

func cleanStereoscopeTemps() {
	files, _ := filepath.Glob("/tmp/stereoscope*")
	for _, f := range files {
		os.RemoveAll(f)
	}
}

func findLatestRelevantRuns(ctx context.Context, client *github.Client, owner, repoName string, maxRuns int, lastProcessedID int64) ([]WorkflowScanTarget, int64, error) {
	if maxRuns <= 0 {
		maxRuns = 5
	}

	if lastProcessedID == -1 {
		return nil, -1, fmt.Errorf("no relevant successful workflow runs found in latest %d workflow runs", maxRuns)
	}

	runs, _, err := client.Actions.ListRepositoryWorkflowRuns(ctx, owner, repoName, &github.ListWorkflowRunsOptions{
		Status: "success",
		ListOptions: github.ListOptions{
			PerPage: maxRuns,
		},
	})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list workflow runs for %s/%s: %w", owner, repoName, err)
	}

	var targets []WorkflowScanTarget
	var highestSeenID int64

	for _, run := range runs.WorkflowRuns {
		if run.GetID() > highestSeenID {
			highestSeenID = run.GetID()
		}

		if run.GetID() <= lastProcessedID {
			log.Printf("      ⏭️  workflow run %s/%s %d already processed, skipping", owner, repoName, run.GetID())
			continue
		}

		event := run.GetEvent()
		if event == "pull_request" || event == "pull_request_target" {
			log.Printf("      ⏭️  Skipping PR workflow run %s/%s %d", owner, repoName, run.GetID())
			continue
		}

		analysis, err := fetchAndAnalyzeRun(ctx, client, owner, repoName, run.GetID())
		if err != nil {
			log.Printf("      ⚠️  failed to analyze workflow run %d for %s/%s: %v", run.GetID(), owner, repoName, err)
			continue
		}

		if analysis == nil {
			continue
		}

		if analysis.DockerImage == "" && !analysis.HasSBOM && analysis.ReleaseVersion == "" {
			log.Printf("      ⏭️  workflow run %s/%s %d has no image/SBOM/release signal", owner, repoName, run.GetID())
			continue
		}

		targets = append(targets, WorkflowScanTarget{
			RunID:     run.GetID(),
			CommitSHA: run.GetHeadSHA(),
			Branch:    run.GetHeadBranch(),
			Analysis:  analysis,
		})
	}

	if len(targets) == 0 {
		checkpoint := highestSeenID
		if checkpoint == 0 {
			checkpoint = -1
		}
		return nil, checkpoint, fmt.Errorf("no relevant successful workflow runs found in latest %d workflow runs", maxRuns)
	}

	for i, j := 0, len(targets)-1; i < j; i, j = i+1, j-1 {
		targets[i], targets[j] = targets[j], targets[i]
	}

	return targets, highestSeenID, nil
}

func fetchAndAnalyzeRun(ctx context.Context, client *github.Client, owner, repo string, runID int64) (*LogAnalysis, error) {
	url, resp, err := client.Actions.GetWorkflowRunLogs(ctx, owner, repo, runID, 3)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	logData, _ := downloadFile(url.String())
	return parseLogs(logData)
}

func downloadSBOMArtifact(ctx context.Context, client *github.Client, owner, repo string, runID int64) ([]byte, error) {
	artifacts, _, err := client.Actions.ListWorkflowRunArtifacts(ctx, owner, repo, runID, &github.ListOptions{PerPage: 100})
	if err != nil {
		return nil, err
	}

	var target *github.Artifact
	for _, a := range artifacts.Artifacts {
		n := strings.ToLower(a.GetName())
		if strings.Contains(n, "sbom") || strings.Contains(n, "cyclonedx") {
			target = a
			break
		}
	}
	if target == nil {
		return nil, fmt.Errorf("no sbom artifact")
	}

	url, _, _ := client.Actions.DownloadArtifact(ctx, owner, repo, target.GetID(), 10)
	zipBytes, _ := downloadFile(url.String())
	r, _ := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	for _, f := range r.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			rc, _ := f.Open()
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("no json")
}

type LogAnalysis struct {
	DockerImage    string
	ReleaseVersion string
	HasSBOM        bool
}

type WorkflowScanTarget struct {
	RunID     int64
	CommitSHA string
	Branch    string
	Analysis  *LogAnalysis
}

func stripANSI(str string) string {
	const ansi = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"
	return regexp.MustCompile(ansi).ReplaceAllString(str, "")
}

func parseLogs(zipData []byte) (*LogAnalysis, error) {
	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, err
	}
	analysis := &LogAnalysis{}
	reManifest := regexp.MustCompile(`(?i).*Created\s+manifest\s+list\s+([^\s]+)`)
	reSBOM := regexp.MustCompile(`(?i)(syft|trivy|cyclonedx|spdx)`)

	for _, f := range r.File {
		rc, _ := f.Open()
		content, _ := io.ReadAll(rc)
		rc.Close()
		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		for scanner.Scan() {
			line := stripANSI(scanner.Text())
			if matches := reManifest.FindStringSubmatch(line); len(matches) > 1 {
				image := strings.TrimSpace(matches[1])
				analysis.DockerImage = image
				parts := strings.Split(image, ":")
				if len(parts) > 1 {
					analysis.ReleaseVersion = parts[len(parts)-1]
				}
			}
			if reSBOM.MatchString(line) {
				analysis.HasSBOM = true
			}
		}
	}
	return analysis, nil
}

func collectGitScanMetadata(repoDir string, commitSHA string) GitScanMetadata {
	meta := GitScanMetadata{CommitVerified: "No"}
	commitSHA = strings.TrimSpace(commitSHA)
	if repoDir == "" || commitSHA == "" {
		return meta
	}

	meta.CommitTimestamp = gitOutput(repoDir, "show", "-s", "--format=%cI", commitSHA)
	meta.CommitAuthors = gitOutput(repoDir, "show", "-s", "--format=%an <%ae>", commitSHA)
	meta.SignedOffBy = extractSignedOffBy(gitOutput(repoDir, "show", "-s", "--format=%B", commitSHA))
	meta.CommittersCount = countUniqueGitOutput(repoDir, "log", "--format=%cN <%cE>", commitSHA+"^.."+commitSHA)
	meta.TotalCommittersCount = countUniqueGitOutput(repoDir, "log", "--format=%cN <%cE>", "--all")
	meta.PrevComponentCommit = gitOutput(repoDir, "rev-parse", commitSHA+"^")
	meta.LinesAdded, meta.LinesDeleted = gitCommitLineStats(repoDir, commitSHA)
	meta.LinesTotal = gitRepoLineTotal(repoDir)

	totalCommits := gitOutput(repoDir, "rev-list", "--count", "HEAD")
	if authorEmail := gitOutput(repoDir, "show", "-s", "--format=%ae", commitSHA); authorEmail != "" {
		authorCommits := gitOutput(repoDir, "rev-list", "--count", "--author="+authorEmail, "HEAD")
		meta.ContribPercentage = calculateContributionPercentage(authorCommits, totalCommits)
	}

	if gitCommitSignatureVerified(repoDir, commitSHA) {
		meta.CommitVerified = "Yes"
	}

	return meta
}

func applyGitScanMetadata(mapping map[string]string, meta GitScanMetadata) {
	setMappingIfNotEmpty(mapping, "GitCommitDate", meta.CommitTimestamp)
	setMappingIfNotEmpty(mapping, "GitCommitTimestamp", meta.CommitTimestamp)
	setMappingIfNotEmpty(mapping, "GitCommitAuthors", meta.CommitAuthors)
	setMappingIfNotEmpty(mapping, "GitCommittersCount", meta.CommittersCount)
	setMappingIfNotEmpty(mapping, "GitTotalCommittersCount", meta.TotalCommittersCount)
	setMappingIfNotEmpty(mapping, "GitContribPercentage", meta.ContribPercentage)
	setMappingIfNotEmpty(mapping, "GitLinesAdded", meta.LinesAdded)
	setMappingIfNotEmpty(mapping, "GitLinesDeleted", meta.LinesDeleted)
	setMappingIfNotEmpty(mapping, "GitLinesTotal", meta.LinesTotal)
	setMappingIfNotEmpty(mapping, "GitPreviousCommit", meta.PrevComponentCommit)
	setMappingIfNotEmpty(mapping, "GitPrevComponentCommit", meta.PrevComponentCommit)
	setMappingIfNotEmpty(mapping, "GitCommitVerified", meta.CommitVerified)
	setMappingIfNotEmpty(mapping, "GitSignedOffBy", meta.SignedOffBy)
}

func setMappingIfNotEmpty(mapping map[string]string, key string, value string) {
	if strings.TrimSpace(value) != "" {
		mapping[key] = value
	}
}

func gitOutput(repoDir string, args ...string) string {
	cmd := exec.Command("git", args...)
	cmd.Dir = repoDir
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func countUniqueGitOutput(repoDir string, args ...string) string {
	out := gitOutput(repoDir, args...)
	if strings.TrimSpace(out) == "" {
		return ""
	}
	seen := make(map[string]struct{})
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			seen[line] = struct{}{}
		}
	}
	return fmt.Sprintf("%d", len(seen))
}

func gitCommitLineStats(repoDir string, commitSHA string) (string, string) {
	cmd := exec.Command("git", "diff", "--numstat", commitSHA+"^", commitSHA)
	cmd.Dir = repoDir
	out, err := cmd.Output()
	if err != nil {
		return "", ""
	}

	var addedTotal int
	var deletedTotal int
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if fields[0] != "-" {
			if n, err := strconv.Atoi(fields[0]); err == nil {
				addedTotal += n
			}
		}
		if fields[1] != "-" {
			if n, err := strconv.Atoi(fields[1]); err == nil {
				deletedTotal += n
			}
		}
	}

	return fmt.Sprintf("%d", addedTotal), fmt.Sprintf("%d", deletedTotal)
}

func gitRepoLineTotal(repoDir string) string {
	filesOut := gitOutput(repoDir, "ls-files")
	if strings.TrimSpace(filesOut) == "" {
		return ""
	}

	total := 0
	for _, file := range strings.Split(filesOut, "\n") {
		file = strings.TrimSpace(file)
		if file == "" {
			continue
		}
		content, err := os.ReadFile(filepath.Join(repoDir, file))
		if err != nil || bytes.IndexByte(content, 0) >= 0 {
			continue
		}
		lines := bytes.Count(content, []byte("\n"))
		if len(content) > 0 && !bytes.HasSuffix(content, []byte("\n")) {
			lines++
		}
		total += lines
	}

	return fmt.Sprintf("%d", total)
}

func gitCommitSignatureVerified(repoDir string, commitSHA string) bool {
	status := gitOutput(repoDir, "show", "-s", "--format=%G?", commitSHA)
	return status == "G" || status == "U"
}

func extractSignedOffBy(commitBody string) string {
	re := regexp.MustCompile(`(?im)^Signed-off-by:\s*(.+)$`)
	matches := re.FindStringSubmatch(commitBody)
	if len(matches) < 2 {
		return ""
	}
	return strings.TrimSpace(matches[1])
}

func calculateContributionPercentage(authorCommits string, totalCommits string) string {
	authorCount, err1 := strconv.Atoi(strings.TrimSpace(authorCommits))
	totalCount, err2 := strconv.Atoi(strings.TrimSpace(totalCommits))
	if err1 != nil || err2 != nil || totalCount == 0 {
		return ""
	}
	return fmt.Sprintf("%.2f%%", float64(authorCount)/float64(totalCount)*100)
}

func applyReleaseMetadataFields(release *model.ProjectRelease, mapping map[string]string) {
	setReleaseField(release, []string{"DockerBasename", "ImageBasename", "Basename"}, mapping["DockerBasename"])
	setReleaseField(release, []string{"DockerDigest", "ImageDigest"}, mapping["DockerSha"])
	setReleaseField(release, []string{"GitRepo", "GitRepository", "GitRepoName", "Repo"}, mapping["GitRepo"])
	setReleaseField(release, []string{"GitTag", "Tag"}, mapping["GitTag"])
	setReleaseField(release, []string{"BuildID", "BuildId"}, mapping["BuildId"])
	setReleaseField(release, []string{"BuildNumber"}, mapping["BuildNumber"])
	setReleaseField(release, []string{"BuildURL", "BuildUrl"}, mapping["BuildUrl"])
	setReleaseField(release, []string{"BuildDate", "BuildTimestamp"}, mapping["BuildDate"])
	setReleaseField(release, []string{"GitCommitDate", "GitCommitTimestamp", "CommitTimestamp"}, mapping["GitCommitDate"])
	setReleaseField(release, []string{"GitCommitAuthors", "CommitAuthors"}, mapping["GitCommitAuthors"])
	setReleaseField(release, []string{"GitCommittersCount", "CommittersCount"}, mapping["GitCommittersCount"])
	setReleaseField(release, []string{"GitTotalCommittersCount", "TotalCommittersCount"}, mapping["GitTotalCommittersCount"])
	setReleaseField(release, []string{"GitContribPercentage", "ContribPercentage"}, mapping["GitContribPercentage"])
	setReleaseField(release, []string{"GitLinesAdded", "LinesAdded"}, mapping["GitLinesAdded"])
	setReleaseField(release, []string{"GitLinesDeleted", "LinesDeleted"}, mapping["GitLinesDeleted"])
	setReleaseField(release, []string{"GitLinesTotal", "LinesTotal"}, mapping["GitLinesTotal"])
	setReleaseField(release, []string{"GitPreviousCommit", "GitPrevComponentCommit", "PrevComponentCommit"}, mapping["GitPreviousCommit"])
	setReleaseField(release, []string{"GitCommitVerified", "CommitVerified"}, mapping["GitCommitVerified"])
	setReleaseField(release, []string{"GitSignedOffBy", "SignedOffBy"}, mapping["GitSignedOffBy"])
}

func setReleaseField(release *model.ProjectRelease, fieldNames []string, value string) {
	value = strings.TrimSpace(value)
	if value == "" || release == nil {
		return
	}

	rv := reflect.ValueOf(release)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return
	}
	elem := rv.Elem()
	if elem.Kind() != reflect.Struct {
		return
	}

	for _, fieldName := range fieldNames {
		field := elem.FieldByName(fieldName)
		if !field.IsValid() || !field.CanSet() {
			continue
		}

		switch field.Kind() {
		case reflect.String:
			field.SetString(value)
			return
		case reflect.Bool:
			field.SetBool(strings.EqualFold(value, "yes") || strings.EqualFold(value, "true"))
			return
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if n, err := strconv.ParseInt(strings.TrimSuffix(value, "%"), 10, field.Type().Bits()); err == nil {
				field.SetInt(n)
				return
			}
		case reflect.Float32, reflect.Float64:
			if n, err := strconv.ParseFloat(strings.TrimSuffix(value, "%"), field.Type().Bits()); err == nil {
				field.SetFloat(n)
				return
			}
		case reflect.Struct:
			if field.Type() == reflect.TypeOf(time.Time{}) {
				if ts, err := time.Parse(time.RFC3339, value); err == nil {
					field.Set(reflect.ValueOf(ts))
					return
				}
			}
		}
	}
}

func buildRelease(mapping map[string]string, projectType string, isPublic bool) *model.ProjectRelease {
	release := model.NewProjectRelease()
	release.Name = getOrDefault(mapping["CompName"], mapping["GitRepoProject"], "unknown")
	release.Version = getOrDefault(mapping["DockerTag"], mapping["GitVersion"], mapping["GitTag"], "0.0.0")
	release.ProjectType = projectType
	release.DockerRepo = mapping["DockerRepo"]
	release.DockerTag = mapping["DockerTag"]
	release.DockerSha = mapping["DockerSha"]
	release.GitBranch = mapping["GitBranch"]
	release.GitCommit = mapping["GitCommit"]
	release.GitOrg = mapping["GitOrg"]
	release.GitRepoProject = mapping["GitRepoProject"]
	release.GitURL = mapping["GitUrl"]
	release.IsPublic = isPublic
	applyReleaseMetadataFields(release, mapping)
	return release
}

func fetchOpenSSFScorecard(gitURL, commitSha string) (*model.ScorecardAPIResponse, float64, error) {
	platform, org, repo, err := parseGitURL(gitURL)
	if err != nil {
		return nil, 0, err
	}
	apiURL := fmt.Sprintf("https://api.securityscorecards.dev/projects/%s/%s/%s", platform, org, repo)
	resp, err := http.Get(apiURL)
	if err != nil || resp.StatusCode != 200 {
		return nil, 0, fmt.Errorf("not found")
	}
	var res model.ScorecardAPIResponse
	json.NewDecoder(resp.Body).Decode(&res)
	res.Repo.Commit = commitSha
	return &res, res.Score, nil
}

func parseGitURL(gitURL string) (p, o, r string, err error) {
	gitURL = strings.TrimPrefix(strings.TrimSuffix(gitURL, ".git"), "https://")
	parts := strings.Split(gitURL, "/")
	if len(parts) < 3 {
		return "", "", "", fmt.Errorf("invalid")
	}
	return parts[0], parts[1], parts[2], nil
}

func populateContentSha(release *model.ProjectRelease) {
	if (release.ProjectType == "docker" || release.ProjectType == "container") && release.DockerSha != "" {
		release.ContentSha = release.DockerSha
	} else {
		release.ContentSha = release.GitCommit
	}
}

func getOrDefault(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func downloadFile(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func generateSBOMFromInput(ctx context.Context, input string) ([]byte, string, error) {
	src, err := syft.GetSource(ctx, input, nil)
	if err != nil {
		return nil, "", err
	}
	s, err := syft.CreateSBOM(ctx, src, nil)
	if err != nil {
		return nil, "", err
	}
	dockerSHA := ""
	if s.Source.Metadata != nil {
		dockerSHA = s.Source.ID
	}
	var buf bytes.Buffer
	enc, _ := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	enc.Encode(&buf, *s)
	return buf.Bytes(), dockerSHA, nil
}

func getInstallationToken(appID, pemStr, installID string) (string, error) {
	block, _ := pem.Decode([]byte(pemStr))
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	claims := jwt.RegisteredClaims{
		Issuer: appID, IssuedAt: jwt.NewNumericDate(time.Now().Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedJWT, _ := token.SignedString(key)
	api := fmt.Sprintf("https://api.github.com/app/installations/%s/access_tokens", installID)
	req, _ := http.NewRequest("POST", api, nil)
	req.Header.Set("Authorization", "Bearer "+signedJWT)
	resp, _ := http.DefaultClient.Do(req)
	var res struct {
		Token string `json:"token"`
	}
	json.NewDecoder(resp.Body).Decode(&res)
	return res.Token, nil
}

func githubCloneURL(token, owner, repoName string) string {
	if token == "" {
		return fmt.Sprintf("https://github.com/%s/%s.git", owner, repoName)
	}
	return fmt.Sprintf("https://x-access-token:%s@github.com/%s/%s.git", token, owner, repoName)
}

func gitCloneCheckout(repoURL, commitSHA, dest string) error {
	commitSHA = strings.TrimSpace(commitSHA)
	if commitSHA == "" {
		return fmt.Errorf("empty commit SHA")
	}

	if err := exec.Command("git", "clone", "--depth", "2", repoURL, dest).Run(); err == nil {
		if err := exec.Command("git", "-C", dest, "checkout", "-b", "relscanner-checkout", commitSHA).Run(); err == nil {
			_ = gitEnsurePreviousCommit(dest, commitSHA)
			return nil
		}
	}

	if err := resetGitDir(dest); err != nil {
		return err
	}
	if err := exec.Command("git", "-C", dest, "init").Run(); err != nil {
		return err
	}
	if err := exec.Command("git", "-C", dest, "remote", "add", "origin", repoURL).Run(); err != nil {
		return err
	}
	if err := exec.Command("git", "-C", dest, "fetch", "--depth", "2", "origin", commitSHA).Run(); err != nil {
		return err
	}
	if err := exec.Command("git", "-C", dest, "checkout", "-b", "relscanner-checkout", "FETCH_HEAD").Run(); err != nil {
		return err
	}
	_ = gitEnsurePreviousCommit(dest, commitSHA)
	return nil
}

func gitCloneCheckoutRef(repoURL, ref, dest string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return fmt.Errorf("empty git ref")
	}

	if err := exec.Command("git", "clone", "--depth", "2", "--branch", ref, repoURL, dest).Run(); err == nil {
		if head, resolveErr := gitResolveHead(dest); resolveErr == nil {
			_ = gitEnsurePreviousCommit(dest, head)
		}
		return nil
	}

	if err := resetGitDir(dest); err != nil {
		return err
	}
	if err := exec.Command("git", "-C", dest, "init").Run(); err != nil {
		return err
	}
	if err := exec.Command("git", "-C", dest, "remote", "add", "origin", repoURL).Run(); err != nil {
		return err
	}

	fetchTagRef := fmt.Sprintf("refs/tags/%s:refs/tags/%s", ref, ref)
	if err := exec.Command("git", "-C", dest, "fetch", "--depth", "2", "origin", fetchTagRef).Run(); err == nil {
		if err := exec.Command("git", "-C", dest, "checkout", ref).Run(); err != nil {
			return err
		}
	} else if err := exec.Command("git", "-C", dest, "fetch", "--depth", "2", "origin", ref).Run(); err == nil {
		if err := exec.Command("git", "-C", dest, "checkout", "FETCH_HEAD").Run(); err != nil {
			return err
		}
	} else {
		return err
	}

	if head, resolveErr := gitResolveHead(dest); resolveErr == nil {
		_ = gitEnsurePreviousCommit(dest, head)
	}
	return nil
}

func resetGitDir(dest string) error {
	if err := os.RemoveAll(dest); err != nil {
		return err
	}
	return os.MkdirAll(dest, 0o755)
}

func gitEnsurePreviousCommit(repoDir, commitSHA string) error {
	commitSHA = strings.TrimSpace(commitSHA)
	if commitSHA == "" {
		resolved, err := gitResolveHead(repoDir)
		if err != nil {
			return err
		}
		commitSHA = resolved
	}

	if err := exec.Command("git", "-C", repoDir, "rev-parse", "--verify", commitSHA+"^").Run(); err == nil {
		return nil
	}

	var lastErr error
	for i := 0; i < 5; i++ {
		if err := exec.Command("git", "-C", repoDir, "fetch", "--deepen", "1", "origin").Run(); err != nil {
			lastErr = err
			break
		}
		if err := exec.Command("git", "-C", repoDir, "rev-parse", "--verify", commitSHA+"^").Run(); err == nil {
			return nil
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("previous commit not available for %s", commitSHA)
}

func gitResolveHead(repoDir string) (string, error) {
	out, err := exec.Command("git", "-C", repoDir, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func postRelease(serverURL string, payload interface{}) error {
	jsonData, _ := json.Marshal(payload)
	resp, err := http.Post(serverURL+"/api/v1/releases", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

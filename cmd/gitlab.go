// Package cmd implements GitLab repository scanning for the relscanner worker.
package cmd

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const gitlabAPI = "https://gitlab.com/api/v4"

// gitLabPipeline represents a GitLab CI pipeline.
type gitLabPipeline struct {
	ID        int64     `json:"id"`
	SHA       string    `json:"sha"`
	Ref       string    `json:"ref"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// gitLabJob represents a GitLab CI job within a pipeline.
type gitLabJob struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Stage         string `json:"stage"`
	ArtifactsFile struct {
		Filename string `json:"filename"`
		Size     int64  `json:"size"`
	} `json:"artifacts_file"`
}

// gitLabProject represents a GitLab project (repository).
type gitLabProject struct {
	ID                int    `json:"id"`
	PathWithNamespace string `json:"path_with_namespace"`
	DefaultBranch     string `json:"default_branch"`
	Archived          bool   `json:"archived"`
	WebURL            string `json:"web_url"`
}

// processGitLabRepo processes a single GitLab repo from an org's tracked_repos.
// Mirrors the GitHub processSingleRepo flow using the GitLab CI API.
// Only successful pipelines on the default branch are considered.
func processGitLabRepo(token, group, repoName string, isPublic bool, processedRepos map[string]int64) error {
	repoKey := fmt.Sprintf("gitlab/%s/%s", group, repoName)
	projectPath := fmt.Sprintf("%s/%s", group, repoName)

	project, err := fetchGitLabProject(token, projectPath)
	if err != nil {
		return fmt.Errorf("failed to fetch gitlab project %s: %w", projectPath, err)
	}

	if project.Archived {
		log.Printf("      ⏭️  Skipping archived GitLab repo: %s", projectPath)
		return nil
	}

	pipeline, err := findLatestSuccessfulPipeline(token, project.ID, project.DefaultBranch)
	if err != nil {
		return fmt.Errorf("no successful pipelines for %s: %w", projectPath, err)
	}

	// Use pipeline ID as the equivalent of GitHub run ID for deduplication
	if lastID, exists := processedRepos[repoKey]; exists && pipeline.ID <= lastID {
		log.Printf("      ⏭️  GitLab %s already processed (pipeline %d)", projectPath, pipeline.ID)
		return nil
	}

	sbomBytes, err := fetchGitLabSBOM(token, project.ID, pipeline.ID)
	if err != nil {
		log.Printf("      ⚠️  No SBOM artifact for GitLab %s pipeline %d: %v", projectPath, pipeline.ID, err)
	}

	// Default to a minimal CycloneDX placeholder if no SBOM was found
	sbomContent := json.RawMessage(`{"bomFormat":"CycloneDX","specVersion":"1.4","components":[]}`)
	if len(sbomBytes) > 0 {
		sbomContent = json.RawMessage(sbomBytes)
	}

	releaseVersion := pipeline.Ref
	if releaseVersion == project.DefaultBranch {
		releaseVersion = "0.0.0-snapshot"
	}

	mapping := map[string]string{
		"CompName":       projectPath,
		"GitRepoProject": repoName,
		"GitOrg":         group,
		"GitCommit":      pipeline.SHA,
		"GitBranch":      pipeline.Ref,
		"BuildId":        fmt.Sprintf("%d", pipeline.ID),
		"GitUrl":         fmt.Sprintf("https://gitlab.com/%s", projectPath),
		"GitTag":         releaseVersion,
		"ProjectType":    "application",
	}

	release := buildRelease(mapping, "application", isPublic)
	populateContentSha(release)

	payload := struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		ObjType     string `json:"obj_type"`
		GitCommit   string `json:"git_commit"`
		GitBranch   string `json:"git_branch"`
		GitOrg      string `json:"git_org"`
		GitURL      string `json:"git_url"`
		ProjectType string `json:"project_type"`
		ContentSha  string `json:"contentsha"`
		SBOM        struct {
			ObjType string          `json:"obj_type"`
			Content json.RawMessage `json:"content"`
		} `json:"sbom"`
	}{
		Name:        release.Name,
		Version:     release.Version,
		ObjType:     "ProjectRelease",
		GitCommit:   release.GitCommit,
		GitBranch:   release.GitBranch,
		GitOrg:      release.GitOrg,
		GitURL:      release.GitURL,
		ProjectType: release.ProjectType,
		ContentSha:  release.ContentSha,
		SBOM: struct {
			ObjType string          `json:"obj_type"`
			Content json.RawMessage `json:"content"`
		}{ObjType: "SBOM", Content: sbomContent},
	}

	if err := postRelease(serverURL, payload); err == nil {
		processedRepos[repoKey] = pipeline.ID
		log.Printf("      🚀 GitLab release %s@%s synced (SHA: %s)", projectPath, releaseVersion, release.ContentSha)
	} else {
		log.Printf("      ⚠️  Failed to post GitLab release %s: %v", projectPath, err)
	}

	return nil
}

// fetchGitLabProject retrieves project metadata by path (e.g. "group/repo").
func fetchGitLabProject(token, projectPath string) (*gitLabProject, error) {
	encoded := strings.ReplaceAll(projectPath, "/", "%2F")
	apiURL := fmt.Sprintf("%s/projects/%s", gitlabAPI, encoded)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("PRIVATE-TOKEN", token)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gitlab returned status %d for project %s", resp.StatusCode, projectPath)
	}

	var project gitLabProject
	if err := json.NewDecoder(resp.Body).Decode(&project); err != nil {
		return nil, err
	}
	return &project, nil
}

// findLatestSuccessfulPipeline returns the most recent successful pipeline
// on the given branch for a GitLab project.
func findLatestSuccessfulPipeline(token string, projectID int, branch string) (*gitLabPipeline, error) {
	apiURL := fmt.Sprintf("%s/projects/%d/pipelines?status=success&ref=%s&per_page=1&order_by=id&sort=desc",
		gitlabAPI, projectID, branch)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("PRIVATE-TOKEN", token)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gitlab pipelines returned status %d", resp.StatusCode)
	}

	var pipelines []gitLabPipeline
	if err := json.NewDecoder(resp.Body).Decode(&pipelines); err != nil {
		return nil, err
	}
	if len(pipelines) == 0 {
		return nil, fmt.Errorf("no successful pipelines on branch %s", branch)
	}
	return &pipelines[0], nil
}

// fetchGitLabSBOM scans pipeline jobs for an SBOM artifact and downloads it.
func fetchGitLabSBOM(token string, projectID int, pipelineID int64) ([]byte, error) {
	apiURL := fmt.Sprintf("%s/projects/%d/pipelines/%d/jobs?per_page=100", gitlabAPI, projectID, pipelineID)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("PRIVATE-TOKEN", token)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gitlab jobs returned status %d", resp.StatusCode)
	}

	var jobs []gitLabJob
	if err := json.NewDecoder(resp.Body).Decode(&jobs); err != nil {
		return nil, err
	}

	for _, job := range jobs {
		jobName := strings.ToLower(job.Name)
		artifactName := strings.ToLower(job.ArtifactsFile.Filename)
		if strings.Contains(jobName, "sbom") || strings.Contains(jobName, "cyclonedx") ||
			strings.Contains(artifactName, "sbom") || strings.Contains(artifactName, "cyclonedx") {
			return downloadGitLabJobArtifact(token, projectID, job.ID)
		}
	}

	return nil, fmt.Errorf("no SBOM job artifact found in pipeline %d", pipelineID)
}

// downloadGitLabJobArtifact downloads the artifact zip for a job and returns
// the content of the first JSON file found inside it.
func downloadGitLabJobArtifact(token string, projectID int, jobID int64) ([]byte, error) {
	apiURL := fmt.Sprintf("%s/projects/%d/jobs/%d/artifacts", gitlabAPI, projectID, jobID)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("PRIVATE-TOKEN", token)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("artifact download returned status %d", resp.StatusCode)
	}

	zipBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read artifact response: %w", err)
	}

	return unzipFirstJSON(zipBytes)
}

// unzipFirstJSON extracts the content of the first .json file in a zip archive.
// Shared by both the GitHub and GitLab SBOM artifact extraction paths.
func unzipFirstJSON(zipBytes []byte) ([]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to open zip: %w", err)
	}

	for _, f := range r.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("failed to open zip entry %s: %w", f.Name, err)
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("no JSON file found in artifact zip")
}

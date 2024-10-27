package js

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/knowledge"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/parser"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	sbom "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js/exceptions"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/workspace"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	exceptionManager "github.com/CodeClarityCE/utility-types/exceptions"
	"github.com/google/uuid"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/properties"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/utils/file"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/utils/project_finder"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/utils/output_generator"
)

// Start is a function that analyzes the source code directory and generates a software bill of materials (SBOM) output.
// It returns an sbom.Output struct containing the analysis results.
func Start(sourceCodeDir string, analysisId uuid.UUID) sbom.Output {
	start := time.Now()

	// Source code directory does not exist
	if !file.CheckDirExists(sourceCodeDir) {
		exceptionManager.AddError(
			"We encountered an error while analysing your project", exceptions.GENERIC_ERROR,
			"The given source code directory does not exist", exceptions.SOURCE_CODE_DIR_DOES_NOT_EXIST_ERROR,
		)
		return output_generator.WriteFailureOutput(sbom.Output{}, start)
	}

	// Read package file
	projectInformation, err := project_finder.ReadPackageFiles(sourceCodeDir)
	if err != nil {
		exceptionManager.AddError(
			"Unable to parse package file, is it a valid package.json?", exceptions.PACKAGE_FILE_PARSING_ERROR,
			"Unable to parse package file, error: "+err.Error(), exceptions.PACKAGE_FILE_PARSING_ERROR,
		)
		return output_generator.WriteFailureOutput(sbom.Output{}, start)
	}

	// package managed manifest files found
	LockFileInformation, err := parser.ParseLockFile(projectInformation)
	if err != nil {
		exceptionManager.AddError(
			"Unable to parse lock file, is it a valid lockfile?", exceptions.LOCK_FILE_PARSING_ERROR,
			"Unable to parse lock file, error: "+err.Error(), exceptions.LOCK_FILE_PARSING_ERROR,
		)
		return output_generator.WriteFailureOutput(sbom.Output{}, start)
	}

	knowledge.UpdateKnowledge(LockFileInformation.Dependencies, analysisId)

	workSpace := workspace.Build(LockFileInformation, projectInformation)

	return generate_output(start, workSpace, projectInformation, LockFileInformation)

}

func generate_output(start time.Time, workSpaceData map[string]sbom.WorkSpace, projectInformation types.ProjectInformation, LockFileInformation types.LockFileInformation) sbom.Output {
	formattedStart, formattedEnd, delta := output_generator.GetAnalysisTiming(start)

	output := sbom.Output{
		WorkSpaces: workSpaceData,
		AnalysisInfo: sbom.AnalysisInfo{
			Paths: sbom.Paths{
				Lockfile:             projectInformation.LockFile,
				PackageFile:          projectInformation.PackageFile,
				RelativeLockFile:     projectInformation.RelativeLockFilePath,
				RelativePackageFile:  projectInformation.RelativePackagePath,
				WorkSpacePackageFile: make(map[string]string),
			},
			Extra: sbom.Extra{
				LockFileVersion:     LockFileInformation.LockFileVersion,
				VersionSeperator:    properties.VERSION_SEPERATOR,
				ImportPathSeperator: properties.IMPORT_PATH_SEPERATOR,
			},
			PackageManager:   projectInformation.PackageManager,
			ProjectName:      projectInformation.PackageFileData.Name,
			Status:           codeclarity.SUCCESS,
			WorkingDirectory: filepath.Dir(projectInformation.LockFile),
			Workspaces: sbom.Workspaces{
				DefaultWorkspaceName:     properties.DEFAULT_WORKSPACE_CHARACTER,
				SelfManagedWorkspaceName: properties.SELF_MANAGED_WORKSPACES_CHARACTER,
				WorkSpacesUsed:           len(projectInformation.PackageFileData.WorkSpaces) > 0,
			},
			Errors: []exceptionManager.Error{},
			Time: sbom.Time{
				AnalysisStartTime: formattedStart,
				AnalysisEndTime:   formattedEnd,
				AnalysisDeltaTime: delta,
			},
		},
	}

	for workspaceKey := range output.WorkSpaces {
		if workspaceKey == properties.SELF_MANAGED_WORKSPACES_CHARACTER {
			continue
		}
		if workspaceKey == properties.DEFAULT_WORKSPACE_CHARACTER {
			output.AnalysisInfo.Paths.WorkSpacePackageFile[workspaceKey] = projectInformation.PackageFile
		} else {
			basePath := filepath.Dir(projectInformation.PackageFile)
			output.AnalysisInfo.Paths.WorkSpacePackageFile[workspaceKey] = fmt.Sprintf("%s/%s/%s", basePath, workspaceKey, "package.json")
		}
	}
	return output
}

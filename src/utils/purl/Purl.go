package purl

// import (
// 	"strings"

// 	linkType "github.com/CodeClarityCE/utility-types/sbom/js/linkType"
// 	"github.com/package-url/packageurl-go"
// )

// // GeneratePurlFromResolvedDep generates a Package URL (PURL) from a ResolvedFilePackage.
// // It takes a ResolvedFilePackage pointer and a boolean flag indicating whether to include the version in the PURL.
// // The function determines the PURL type based on the LinkType of the package and constructs the PURL accordingly.
// // If the LinkType is PACKAGE_MANAGED, it sets the PURL type to "npm" and extracts the name and namespace from the package.
// // If the LinkType is GITHUB or GITLAB, it sets the PURL type to "github" or the GitLab host, and extracts the name, namespace, and project from the package's parsed Git URL.
// // If the LinkType is UNKOWN_GIT_SERVER, it sets the PURL name and namespace from the package's parsed Git URL.
// // If the LinkType is not recognized, it returns an empty string.
// // Finally, it creates a PackageURL object using the determined PURL type, name, namespace, version, and qualifiers, and returns the string representation of the PURL.
// func GeneratePurlFromResolvedDep(pkg *schemas.ResolvedFilePackage, addVersion bool) string {
// 	purlType := ""
// 	purlName := ""
// 	purlNameSpace := ""

// 	switch pkg.LinkType {
// 	case linkType.PACKAGE_MANAGED:
// 		purlType = "npm"
// 		purlName = pkg.Name
// 		if pkg.Scoped {
// 			nameArr := strings.Split(pkg.Name, "/")
// 			purlNameSpace = nameArr[0]
// 			purlName = nameArr[1]
// 		}
// 	case linkType.GITHUB:
// 		purlType = "github"
// 		// purlName = pkg.Name
// 		purlName = pkg.ParsedGitUrl.Project
// 		purlNameSpace = pkg.ParsedGitUrl.User
// 	case linkType.GITLAB:
// 		purlType = pkg.ParsedGitUrl.Host
// 		// purlName = pkg.Name
// 		purlName = pkg.ParsedGitUrl.Project
// 		purlNameSpace = pkg.ParsedGitUrl.User
// 	case linkType.UNKOWN_GIT_SERVER:
// 		// purlName = pkg.ParsedGitUrl.Project
// 		purlName = pkg.ParsedGitUrl.Project
// 		purlNameSpace = pkg.ParsedGitUrl.User
// 	default:
// 		return "" // case a file dependency, is not a package
// 	}

// 	var purl *packageurl.PackageURL
// 	if addVersion {
// 		purl = packageurl.NewPackageURL(purlType, purlNameSpace, purlName, pkg.Version, packageurl.Qualifiers{}, "")
// 	} else {
// 		purl = packageurl.NewPackageURL(purlType, purlNameSpace, purlName, "", packageurl.Qualifiers{}, "")
// 	}

// 	return purl.ToString()
// }

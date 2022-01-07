package v22

import "time"

const (
	// PredicateSPDX represents a SBOM using the SPDX standard.
	// The SPDX mandates 'spdxVersion' field, so predicate type can omit
	// version.
	PredicateSPDX = "https://spdx.dev/Document"
)

// ProvenanceSPDX is the SPDX predicate definition.
type SPDXPredicate struct {
	SPDXID                     string                          `json:"SPDXID"`
	SpdxVersion                string                          `json:"spdxVersion"`
	CreationInfo               SPDXCreationInfo                `json:"creationInfo"`
	Name                       string                          `json:"name"`
	DataLicense                string                          `json:"dataLicense,omitempty"`
	Comment                    string                          `json:"comment,omitempty"`
	DocumentNamespace          string                          `json:"documentNamespace"`
	DocumentDescribes          []string                        `json:"documentDescribes"`
	Packages                   []SPDXPackage                   `json:"packages"`
	Relationships              []SPDXRelationship              `json:"relationships"`
	HasExtractedLicensingInfos []SPDXHasExtractedLicensingInfo `json:"hasExtractedLicensingInfos"`
}

type SPDXCreationInfo struct {
	Created            *time.Time `json:"created,omitempty"`
	Creators           []string   `json:"creators"`
	LicenseListVersion string     `json:"licenseListVersion"`
}

type SPDXPackage struct {
	Name             string         `json:"name"`
	SPDXID           string         `json:"SPDXID"`
	VersionInfo      string         `json:"versionInfo"`
	DownloadLocation string         `json:"downloadLocation"`
	FilesAnalyzed    bool           `json:"filesAnalyzed,omitempty"`
	LicenseConcluded string         `json:"licenseConcluded,omitempty"`
	LicenseDeclared  string         `json:"licenseDeclared,omitempty"`
	CopyrightText    string         `json:"copyrightText,omitempty"`
	PackageFilename  string         `json:"packageFilename,omitempty"`
	Checksums        []SPDXChecksum `json:"checksums,omitempty"`
	Comment          string         `json:"comment,omitempty"`
}

type SPDXChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type SPDXRelationship struct {
	SpdxElementId      string `json:"spdxElementId"`
	RelatedSpdxElement string `json:"relatedSpdxElement"`
	RelationshipType   string `json:"relationshipType"`
}

type SPDXHasExtractedLicensingInfo struct {
	ExtractedText string `json:"extractedText"`
	LicenseId     string `json:"licenseId"`
}

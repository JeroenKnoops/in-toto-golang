package v22

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDecodeSPDXPredicate(t *testing.T) {
	// Data from example in specification for generalized link format,
	// subject and materials trimmed.
	var data = `
{
	"SPDXID": "SPDXRef-DOCUMENT",
	"spdxVersion": "SPDX-2.2",
	"creationInfo": {
		"created": "2020-08-19T08:38:00Z",
		"creators": [
			"Tool: tern-2.9.0"
		],
		"licenseListVersion": "3.8"
	},
	"name": "Test SBOM report",
	"dataLicense": "Data License",
	"comment": "Comment field on root element",
	"documentNamespace": "Document Namespace",
	"documentDescribes": [
		"SPDXRef-sbom-image-name"
	],
	"packages": [
		{
		  "name": "organization/image-name",
		  "SPDXID": "SPDXRef-sbom-image-name",
		  "versionInfo": "latest",
		  "downloadLocation": "Download Location",
		  "filesAnalyzed": false,
		  "licenseConcluded": "License concluded",
		  "licenseDeclared": "License declared",
		  "copyrightText": "Copyright Text"
		},
		{
		  "name": "package",
		  "SPDXID": "SPDXRef-package",
		  "packageFileName": "packageFileName",
		  "downloadLocation": "Download Location",
		  "filesAnalyzed": false,
		  "checksums": [
			  {
				  "algorithm": "SHA256",
				  "checksumValue": "checksum hash"
			  }
		  ],
		  "licenseConcluded": "License concluded",
		  "licenseDeclared": "License declared",
		  "copyrightText": "Copyright Text",
		  "comment": "This is a comment on package level"
		}
	],
	"relationships": [
		{
		  "spdxElementId": "SPDXRef-DOCUMENT",
		  "relatedSpdxElement": "SPDXRef-sbom-image-name",
		  "relationshipType": "DESCRIBES"
		}
	],
	"hasExtractedLicensingInfos": [
		{
		  "extractedText": "MPL-2.0 AND MIT",
		  "licenseId": "LicenseRef-xxxxxxx"
		}
	]
}
`
	var testTime = time.Unix(1597826280, 0)
	var want = SPDXPredicate{
		SPDXID:      "SPDXRef-DOCUMENT",
		SpdxVersion: "SPDX-2.2",
		CreationInfo: SPDXCreationInfo{
			Created:            &testTime,
			Creators:           []string{"Tool: tern-2.9.0"},
			LicenseListVersion: "3.8",
		},
		Name:              "Test SBOM report",
		DataLicense:       "Data License",
		Comment:           "Comment field on root element",
		DocumentNamespace: "Document Namespace",
		DocumentDescribes: []string{"SPDXRef-sbom-image-name"},
		Packages: []SPDXPackage{
			{
				Name:             "organization/image-name",
				SPDXID:           "SPDXRef-sbom-image-name",
				VersionInfo:      "latest",
				DownloadLocation: "Download Location",
				FilesAnalyzed:    false,
				LicenseConcluded: "License concluded",
				LicenseDeclared:  "License declared",
				CopyrightText:    "Copyright Text",
			},
			{
				Name:             "package",
				SPDXID:           "SPDXRef-package",
				PackageFilename:  "packageFileName",
				DownloadLocation: "Download Location",
				FilesAnalyzed:    false,
				Checksums: []SPDXChecksum{
					{
						Algorithm:     "SHA256",
						ChecksumValue: "checksum hash",
					},
				},
				LicenseConcluded: "License concluded",
				LicenseDeclared:  "License declared",
				CopyrightText:    "Copyright Text",
				Comment:          "This is a comment on package level",
			},
		},
		Relationships: []SPDXRelationship{
			{
				SpdxElementId:      "SPDXRef-DOCUMENT",
				RelatedSpdxElement: "SPDXRef-sbom-image-name",
				RelationshipType:   "DESCRIBES",
			},
		},
		HasExtractedLicensingInfos: []SPDXHasExtractedLicensingInfo{
			{
				ExtractedText: "MPL-2.0 AND MIT",
				LicenseId:     "LicenseRef-xxxxxxx",
			},
		},
	}
	var got SPDXPredicate

	if err := json.Unmarshal([]byte(data), &got); err != nil {
		t.Errorf("failed to unmarshal json: %s\n", err)
		return
	}

	// Make sure parsed time have same location set, location is only used
	// for display purposes.
	loc := want.CreationInfo.Created.Location()
	tmp := got.CreationInfo.Created.In(loc)
	got.CreationInfo.Created = &tmp

	assert.Equal(t, want, got, "Unexpected object after decoding")

}

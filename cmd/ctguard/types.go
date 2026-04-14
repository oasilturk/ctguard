package main

// Finding represents a single diagnostic finding from CTGuard analysis.
type Finding struct {
	Pos        string `json:"pos"`
	Message    string `json:"message"`
	Rule       string `json:"rule,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

// SARIF 2.1.0 structures

type SarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SarifRule `json:"rules"`
}

type SarifRule struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	ShortDescription SarifMessage       `json:"shortDescription"`
	FullDescription  SarifMessage       `json:"fullDescription"`
	HelpURI          string             `json:"helpUri"`
	DefaultConfig    SarifDefaultConfig `json:"defaultConfiguration"`
}

type SarifDefaultConfig struct {
	Level string `json:"level"`
}

type SarifMessage struct {
	Text string `json:"text"`
}

type SarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SarifMessage    `json:"message"`
	Locations []SarifLocation `json:"locations"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           *SarifRegion          `json:"region,omitempty"`
}

type SarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type SarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

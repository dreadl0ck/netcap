package dbs

type NVD2 struct {
	ResultsPerPage  int    `json:"resultsPerPage"`
	StartIndex      int    `json:"startIndex"`
	TotalResults    int    `json:"totalResults"`
	Format          string `json:"format"`
	Version         string `json:"version"`
	Timestamp       string `json:"timestamp"`
	Vulnerabilities []struct {
		Cve struct {
			ID               string        `json:"id"`
			SourceIdentifier string        `json:"sourceIdentifier"`
			Published        string        `json:"published"`
			LastModified     string        `json:"lastModified"`
			VulnStatus       string        `json:"vulnStatus"`
			CveTags          []interface{} `json:"cveTags"`
			Descriptions     []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV2 []struct {
					Source   string `json:"source"`
					Type     string `json:"type"`
					CvssData struct {
						Version               string  `json:"version"`
						VectorString          string  `json:"vectorString"`
						BaseScore             float64 `json:"baseScore"`
						AccessVector          string  `json:"accessVector"`
						AccessComplexity      string  `json:"accessComplexity"`
						Authentication        string  `json:"authentication"`
						ConfidentialityImpact string  `json:"confidentialityImpact"`
						IntegrityImpact       string  `json:"integrityImpact"`
						AvailabilityImpact    string  `json:"availabilityImpact"`
					} `json:"cvssData"`
					BaseSeverity            string  `json:"baseSeverity"`
					ExploitabilityScore     float64 `json:"exploitabilityScore"`
					ImpactScore             float64 `json:"impactScore"`
					AcInsufInfo             bool    `json:"acInsufInfo"`
					ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
					ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
					ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
					UserInteractionRequired bool    `json:"userInteractionRequired"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
			Weaknesses []struct {
				Source      string `json:"source"`
				Type        string `json:"type"`
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					Operator string `json:"operator"`
					Negate   bool   `json:"negate"`
					CpeMatch []struct {
						Vulnerable            bool   `json:"vulnerable"`
						Criteria              string `json:"criteria"`
						MatchCriteriaID       string `json:"matchCriteriaId"`
						VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
						VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
						VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
			References []struct {
				URL    string `json:"url"`
				Source string `json:"source"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

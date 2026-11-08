package analyst

// SourceSelection never permits an implicit active-capture fallback.
type SourceSelection struct {
	SessionID string  `json:"sessionId,omitempty"`
	InputFile string  `json:"inputFile,omitempty"`
	Binding   Binding `json:"binding"`
}
type CatalogueRequest struct {
	Page                   *CataloguePage    `json:"page,omitempty"`
	ExpectedSnapshotSHA256 string            `json:"expectedSnapshotSHA256,omitempty"`
	Sources                []SourceSelection `json:"sources"`
	Query                  Query             `json:"query"`
}
type ResolveRequest struct {
	Source    SourceSelection `json:"source"`
	Reference Reference       `json:"reference"`
}
type OccurrencesRequest struct {
	Source SourceSelection `json:"source"`
	Type   string          `json:"type"`
}
type WorkspaceRequest struct {
	Source           SourceSelection `json:"source"`
	Document         *Document       `json:"document,omitempty"`
	ExpectedRevision int             `json:"expectedRevision"`
}
type LogReviewRequest struct {
	Source  SourceSelection `json:"source"`
	File    string          `json:"file"`
	Start   int             `json:"start"`
	End     int             `json:"end"`
	Approve *LogReview      `json:"approve,omitempty"`
}
type InspectRequest struct {
	Source SourceSelection `json:"source"`
}

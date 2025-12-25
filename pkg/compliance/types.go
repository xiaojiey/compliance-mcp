package compliance

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ComplianceScanPhase represents the scan phase
type ComplianceScanPhase string

const (
	PhasePending      ComplianceScanPhase = "PENDING"
	PhaseLaunching    ComplianceScanPhase = "LAUNCHING"
	PhaseRunning      ComplianceScanPhase = "RUNNING"
	PhaseAggregating  ComplianceScanPhase = "AGGREGATING"
	PhaseDone         ComplianceScanPhase = "DONE"
)

// ComplianceScanResult represents the scan result
type ComplianceScanResult string

const (
	ResultNotAvailable  ComplianceScanResult = "NOT-AVAILABLE"
	ResultCompliant     ComplianceScanResult = "COMPLIANT"
	ResultNonCompliant  ComplianceScanResult = "NON-COMPLIANT"
	ResultError         ComplianceScanResult = "ERROR"
	ResultInconsistent  ComplianceScanResult = "INCONSISTENT"
	ResultNotApplicable ComplianceScanResult = "NOT-APPLICABLE"
)

// ComplianceCheckStatus represents the check status
type ComplianceCheckStatus string

const (
	CheckPass   ComplianceCheckStatus = "PASS"
	CheckFail   ComplianceCheckStatus = "FAIL"
	CheckManual ComplianceCheckStatus = "MANUAL"
	CheckError  ComplianceCheckStatus = "ERROR"
	CheckInfo   ComplianceCheckStatus = "INFO"
)

// ComplianceScanType represents the type of scan
type ComplianceScanType string

const (
	ScanTypeNode     ComplianceScanType = "Node"
	ScanTypePlatform ComplianceScanType = "Platform"
)

// ComplianceSuite represents a compliance suite
type ComplianceSuite struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ComplianceSuiteSpec   `json:"spec,omitempty"`
	Status            ComplianceSuiteStatus `json:"status,omitempty"`
}

type ComplianceSuiteSpec struct {
	AutoApplyRemediations bool                       `json:"autoApplyRemediations,omitempty"`
	Schedule              string                     `json:"schedule,omitempty"`
	Scans                 []ComplianceScanSpecWrapper `json:"scans"`
}

type ComplianceScanSpecWrapper struct {
	Name string `json:"name,omitempty"`
	// Other fields as needed
}

type ComplianceSuiteStatus struct {
	Phase        ComplianceScanPhase             `json:"phase,omitempty"`
	Result       ComplianceScanResult            `json:"result,omitempty"`
	ErrorMessage string                          `json:"errorMessage,omitempty"`
	ScanStatuses []ComplianceScanStatusWrapper `json:"scanStatuses,omitempty"`
}

type ComplianceScanStatusWrapper struct {
	Name                 string               `json:"name,omitempty"`
	Phase                ComplianceScanPhase  `json:"phase,omitempty"`
	Result               ComplianceScanResult `json:"result,omitempty"`
}

// ComplianceScan represents a compliance scan
type ComplianceScan struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ComplianceScanSpec   `json:"spec,omitempty"`
	Status            ComplianceScanStatus `json:"status,omitempty"`
}

type ComplianceScanSpec struct {
	ScanType ComplianceScanType `json:"scanType,omitempty"`
	Profile  string             `json:"profile,omitempty"`
	Content  string             `json:"content,omitempty"`
}

type ComplianceScanStatus struct {
	Phase        ComplianceScanPhase  `json:"phase,omitempty"`
	Result       ComplianceScanResult `json:"result,omitempty"`
	ErrorMessage string               `json:"errorMessage,omitempty"`
	StartTimestamp *metav1.Time       `json:"startTimestamp,omitempty"`
	Warnings       string             `json:"warnings,omitempty"`
}

// ComplianceCheckResult represents a check result
type ComplianceCheckResult struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	ID                string                `json:"id,omitempty"`
	Status            ComplianceCheckStatus `json:"status,omitempty"`
	Severity          string                `json:"severity,omitempty"`
	Description       string                `json:"description,omitempty"`
	Instructions      string                `json:"instructions,omitempty"`
	Rationale         string                `json:"rationale,omitempty"`
}

// ComplianceRemediation represents a remediation
type ComplianceRemediation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ComplianceRemediationSpec   `json:"spec,omitempty"`
	Status            ComplianceRemediationStatus `json:"status,omitempty"`
}

type ComplianceRemediationSpec struct {
	Apply bool `json:"apply,omitempty"`
}

type ComplianceRemediationStatus struct {
	ApplicationState string `json:"applicationState,omitempty"`
}

// SuiteLabel is the label used to identify suite ownership
const SuiteLabel = "compliance.openshift.io/suite"

// ScanLabel is the label used to identify scan ownership
const ScanLabel = "compliance.openshift.io/scan-name"

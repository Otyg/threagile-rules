package main

import (
	"github.com/threagile/threagile/model"
)

type accidentalLoggingOfSensitiveDataRule string

var CustomRiskRule accidentalLoggingOfSensitiveDataRule

func (r accidentalLoggingOfSensitiveDataRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "accidental-logging-of-sensitive-data",
		Title:                      "Accidental Logging of Sensitive Data",
		Description:                "",
		Impact:                     "",
		ASVS:                       "V7.1 - Log Content",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#data-to-exclude",
		Action:                     "Review logging statements",
		Mitigation:                 "Review log statements and ensure that sensitive data, such as personal indenfiable information and credentials, is not logged without a legit reason.",
		Check:                      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:                   model.Development,
		STRIDE:                     model.InformationDisclosure,
		DetectionLogic:             "Entities processing, or storing, data with confidentiality restricted or higher which sends data to a monitoring target.",
		RiskAssessment:             "",
		FalsePositives:             "",
		ModelFailurePossibleReason: false,
		CWE:                        532,
	}
}

func (r accidentalLoggingOfPiiRule) SupportedTags() []string {
	return []string{"PII"}
}

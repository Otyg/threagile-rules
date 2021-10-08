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
		Description:                "When storing or processing sensitive data there is a risk that the data is written to logfiles.",
		Impact:                     "Bypassing access controls to the sensitive data",
		ASVS:                       "V7.1 - Log Content",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#data-to-exclude",
		Action:                     "Review logging statements",
		Mitigation:                 "Review log statements and ensure that sensitive data, such as personal indenfiable information and credentials, is not logged without a legit reason.",
		Check:                      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:                   model.Development,
		STRIDE:                     model.InformationDisclosure,
		DetectionLogic:             "Entities processing, or storing, data with confidentiality restricted or higher which sends data to a monitoring target.",
		RiskAssessment:             "",
		FalsePositives:             "If it's ok to write the data to log, then this can be considered a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        532,
	}
}

func (r accidentalLoggingOfSensitiveDataRule) SupportedTags() []string {
	return []string{"PII"}
}

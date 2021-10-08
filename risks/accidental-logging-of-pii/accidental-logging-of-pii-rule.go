package main

import (
	"github.com/threagile/threagile/model"
)

type accidentalLoggingOfPiiRule string

var CustomRiskRule accidentalLoggingOfPiiRule

func (r accidentalLoggingOfPiiRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "accidental-logging-of-pii",
		Title:                      "Accidental Logging of Personal Identifiable Information",
		Description:                "",
		Impact:                     "",
		ASVS:                       "V7.1 - Log Content",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#data-to-exclude",
		Action:                     "Review logging statements",
		Mitigation:                 "Review log statements and ensure that personal indenfiable information is not logged without a legit reason.",
		Check:                      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:                   model.Development,
		STRIDE:                     model.InformationDisclosure,
		DetectionLogic:             "",
		RiskAssessment:             "",
		FalsePositives:             "",
		ModelFailurePossibleReason: false,
		CWE:                        532,
	}
}

func (r accidentalLoggingOfPiiRule) SupportedTags() []string {
	return []string{"PII"}
}

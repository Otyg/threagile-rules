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
	return []string{"PII", "financial", "credential"}
}

func GenerateRisks(r accidentalLoggingOfSensitiveDataRule) []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.OutOfScope || technicalAsset.Technology == model.Monitoring {
			continue
		}
		hasSensitiveData := false
		impact := model.MediumImpact
		for _, data := range append(technicalAsset.DataAssetsProcessedSorted(), technicalAsset.DataAssetsStoredSorted()...) {
			if data.Confidentiality >= model.Restricted {
				hasSensitiveData = true
				if data.Confidentiality == model.Confidential && impact == model.MediumImpact {
					impact = model.HighImpact
				}
				if data.Confidentiality == model.StrictlyConfidential && impact <= model.HighImpact {
					impact = model.VeryHighImpact
				}
			}
		}
		if hasSensitiveData {
			commLinks := technicalAsset.CommunicationLinks
			for _, commLink := range commLinks {
				destination := model.ParsedModelRoot.TechnicalAssets[commLink.TargetId]
				if destination.Technology == model.Monitoring {
					risks = append(risks, createRisk(technicalAsset, commLink, impact))
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, incomingAccess model.CommunicationLink, impact model.RiskExploitationImpact) model.Risk {
	risk := model.Risk{
		Category:               CustomRiskRule.Category(),
		Severity:               model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood: model.Unlikely,
		ExploitationImpact:     impact,
		Title: "<b>Potential logging of sensitive data</b> over communication link <b>" + incomingAccess.Title + "</b> " +
			"from <b>" + model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId].Title + "</b> " +
			"to <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: incomingAccess.Id,
		DataBreachProbability:           model.Improbable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + incomingAccess.Id + "@" + model.ParsedModelRoot.TechnicalAssets[incomingAccess.SourceId].Id + "@" + technicalAsset.Id
	return risk
}

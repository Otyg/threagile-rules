package main

import (
	"github.com/threagile/threagile/model"
)

type accidentalLoggingOfSensitiveDataRule string

var CustomRiskRule accidentalLoggingOfSensitiveDataRule

func (r accidentalLoggingOfSensitiveDataRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "accidental-logging-of-sensitive-data",
		Title:                      "Logging of Sensitive Data",
		Description:                "When storing or processing sensitive data there is a risk that the data is written to logfiles.",
		Impact:                     "Bypassing access controls to the sensitive data",
		ASVS:                       "v4.0.2-7.1 - Log Content",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#data-to-exclude",
		Action:                     "Logging and monitoring",
		Mitigation:                 "Review log statements and ensure that sensitive data, such as personal indenfiable information and credentials, is not logged without a legit reason.",
		Check:                      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:                   model.Development,
		STRIDE:                     model.InformationDisclosure,
		DetectionLogic:             "Entities processing, or storing, data with confidentiality class restricted or higher which sends data to a monitoring target.",
		RiskAssessment:             "The risk rating depends on the sensitivity of the data processed or stored",
		FalsePositives:             "None, either the risk is mitigated or accepted",
		ModelFailurePossibleReason: false,
		CWE:                        532,
	}
}

func (r accidentalLoggingOfSensitiveDataRule) SupportedTags() []string {
	return []string{"PII", "credential"}
}

func (r accidentalLoggingOfSensitiveDataRule) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.OutOfScope || technicalAsset.Technology == model.Monitoring {
			continue
		}
		hasSensitiveData := false
		sensitiveData := make([]string, 0)
		impact := model.MediumImpact
		datas := append(technicalAsset.DataAssetsProcessedSorted(), technicalAsset.DataAssetsStoredSorted()...)
		for _, data := range datas {
			if data.Confidentiality >= model.Restricted || data.IsTaggedWithAny(r.SupportedTags()...) {
				hasSensitiveData = true
				if data.Confidentiality == model.Confidential && impact == model.MediumImpact {
					impact = model.HighImpact
				}
				if data.Confidentiality == model.StrictlyConfidential && impact <= model.HighImpact {
					impact = model.VeryHighImpact
				}
				sensitiveData = append(sensitiveData, data.Id)
			}
		}
		if hasSensitiveData {
			commLinks := technicalAsset.CommunicationLinks
			for _, commLink := range commLinks {
				destination := model.ParsedModelRoot.TechnicalAssets[commLink.TargetId]
				if destination.Technology == model.Monitoring {
					risks = append(risks, createRisk(technicalAsset, impact, sensitiveData))
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact, dataIds []string) model.Risk {
	title := "<b>Logging of Sensitive Data</b> risk at <b>" + technicalAsset.Title + "</b>"
	risk := model.Risk{
		Category:                     CustomRiskRule.Category(),
		Severity:                     model.CalculateSeverity(model.Likely, impact),
		ExploitationLikelihood:       model.Likely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Possible,
		DataBreachTechnicalAssetIDs:  dataIds,
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}

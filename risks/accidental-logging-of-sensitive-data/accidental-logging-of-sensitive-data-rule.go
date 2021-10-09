package main

import (
	"github.com/threagile/threagile/model"
)

type testRule string

var CustomRiskRule testRule

func (r testRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "accidental-logging-of-sensitive-data",
		Title:                      "Logging of Sensitive Data",
		Description:                "When storing or processing sensitive data there is a risk that the data is written to logfiles.",
		Impact:                     "Bypassing access controls to the sensitive data",
		ASVS:                       "V7.1 - Log Content",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#data-to-exclude",
		Action:                     "Review logging statements",
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

func (r testRule) SupportedTags() []string {
	return []string{}
}

func (r testRule) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.OutOfScope || technicalAsset.Technology == model.Monitoring {
			continue
		}
		hasSensitiveData := false
		impact := model.MediumImpact
		datas := append(technicalAsset.DataAssetsProcessedSorted(), technicalAsset.DataAssetsStoredSorted()...)
		for _, data := range datas {
			// TODO: Consider data tagged with PII, financial or credential as sensitive irregardless of classification
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
					risks = append(risks, createRisk(technicalAsset, impact))
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact) model.Risk {
	title := "<b>Logging of Sensitive Data</b> risk at <b>" + technicalAsset.Title + "</b>"
	risk := model.Risk{
		Category:                     CustomRiskRule.Category(),
		Severity:                     model.CalculateSeverity(model.Likely, impact),
		ExploitationLikelihood:       model.Likely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}

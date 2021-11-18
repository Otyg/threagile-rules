package main

import (
	"github.com/threagile/threagile/model"
)

type useOfWeakCrypto string

var CustomRiskRule useOfWeakCrypto

func (r useOfWeakCrypto) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "use-of-weak-cryptograhpy-at-rest",
		Title:                      "Use Of Weak Cryptography At Rest",
		Description:                "To avoid weak cryptography ensure to use algoritms, modes and libraries that has been vetted and proven by industry and/or governments.",
		Impact:                     "Weak cryptography can result in information disclosure and a false sense of security.",
		ASVS:                       "v4.0.3-6.2 - Stored cryptography: Algorithms",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
		Action:                     "Cryptography",
		Mitigation:                 "Ensure to use algoritms, modes and libraries that has been vetted and proven by industry and/or governments.",
		Check:                      "Referenced ASVS chapters and cheat sheets",
		Function:                   model.Development,
		STRIDE:                     model.InformationDisclosure,
		DetectionLogic:             "Encrypted technical assets that stores data",
		RiskAssessment:             "Risk is based on the confidentiality score of stored data.",
		FalsePositives:             "None",
		ModelFailurePossibleReason: false,
		CWE:                        327,
	}
}
func (r useOfWeakCrypto) SupportedTags() []string {
	return []string{}
}
func (r useOfWeakCrypto) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		techAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if techAsset.OutOfScope || techAsset.Technology.IsClient() {
			continue
		}
		if techAsset.Encryption != model.NoneEncryption {
			var mostRelevantDataAssetId string
			var highestConfidentiality model.Confidentiality = model.Public
			var impact model.RiskExploitationImpact
			for _, data := range techAsset.DataAssetsStoredSorted() {
				if data.Confidentiality >= highestConfidentiality {
					mostRelevantDataAssetId = data.Id
					highestConfidentiality = data.Confidentiality
					switch data.Confidentiality {
					case model.Restricted:
						impact = model.MediumImpact
					case model.Confidential:
						impact = model.HighImpact
					case model.StrictlyConfidential:
						impact = model.VeryHighImpact
					default:
						impact = model.LowImpact
					}
				}
			}
			risks = append(risks, createRisk(techAsset, impact, mostRelevantDataAssetId))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact, mostRelevantDataAssetId string) model.Risk {
	title := "<b>Use of weak cryptography at rest</b> risk at <b>" + technicalAsset.Title + "</b>"
	risk := model.Risk{
		Category:                     CustomRiskRule.Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
		MostRelevantDataAssetId:      mostRelevantDataAssetId,
		DataBreachProbability:        model.Possible,
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}

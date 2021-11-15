package main

import (
	"github.com/threagile/threagile/model"
)

type secureCommunication string

var CustomRiskRule secureCommunication

func (r secureCommunication) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "use-of-weak-cryptograhpy",
		Title:                      "Use Of Weak Cryptography",
		Description:                "To avoid weak cryptography ensure to use algoritms, modes and libraries that has been vetted and proven by industry and/or governments.",
		Impact:                     "Weak cryptography can result in information disclosure and a false sense of security.",
		ASVS:                       "v4.0.3-6.2 - Stored cryptography: Algorithms",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
		Action:                     "Cryptography",
		Mitigation:                 "Use vetted and proved cryptographic libraries, avoid custom coded routines.",
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
func (r secureCommunication) SupportedTags() []string {
	return []string{}
}
func (r secureCommunication) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact, mostRelevantDataAssetId string) model.Risk {
	title := "<b>Use of weak cryptography</b> risk at <b>" + technicalAsset.Title + "</b>"
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

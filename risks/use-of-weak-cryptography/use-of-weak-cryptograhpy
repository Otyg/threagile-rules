package main

import (
	"github.com/threagile/threagile/model"
)

type useOfWeakCryptography string

var CustomRiskRule useOfWeakCryptography

func (r useOfWeakCryptography) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "use-of-weak-cryptograhpy",
		Title:                      "Use Of Weak Cryptography",
		Description:                "To avoid weak cryptography ensure to use algoritms, modes and libraries that has been vetted and proven by industry and/or governments.",
		Impact:                     "Weak cryptography can result in information disclosure and a false sense of security.",
		ASVS:                       "v4.0.3-6.2 - Stored cryptography: Algorithms",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html, https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README.html, https://csrc.nist.gov/publications/detail/fips/140/3/final",
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

func (r useOfWeakCryptography) SupportedTags() []string {
	return []string{}
}

func (r useOfWeakCryptography) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		techAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if techAsset.OutOfScope || techAsset.Technology.IsClient() {
			continue
		}
		if techAsset.Encryption != "None" {

		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact) model.Risk {
	title := "<b>Use of weak cryptography</b> risk at <b>" + technicalAsset.Title + "</b>"
	risk := model.Risk{
		Category:                     CustomRiskRule.Category(),
		Severity:                     model.CalculateSeverity(model.Unlikely, impact),
		ExploitationLikelihood:       model.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachTechnicalAssetIDs:  []string{},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}

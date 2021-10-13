package main

import (
	"github.com/threagile/threagile/model"
)

type longLivedCredentialOutsideOfVault string

var CustomRiskRule longLivedCredentialOutsideOfVault

func (r longLivedCredentialOutsideOfVault) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "credential-stored-outside-of-vault",
		Title:                      "Credential Stored Outside Of Vault",
		Description:                "Secret data, such as credentials and encryption keys, must be protected and managed in a secure way to minimize the risk of exposure. The recommended solution is to keep secret data in a dedicated system (vault) and only store access credentials to this system on other technical assets.",
		Impact:                     "If a hardcoded secret is exposed considerable work must be done to rotate it",
		ASVS:                       "v4.0.2-1.6.3 - Cryptographic Architectural Requirements, v4.0.2-6.4 - Secret Management",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#key-management, https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html#key-management-lifecycle-best-practices",
		Action:                     "Secret management",
		Mitigation:                 "Manage secrets and credentials according to ASVS and the cheat sheets referenced",
		Check:                      "Is secret data (i.e. credentials) protected well enough? Has relevant parts of referenced ASVS and cheat sheets been applied?",
		Function:                   model.Operations,
		STRIDE:                     model.InformationDisclosure,
		DetectionLogic:             "Data assets tagged with any of the supported tags is stored on a technical asset that is not a vault",
		RiskAssessment:             "Impact and severity is calculated based on the tags available on the data asset and the confidentiality class of the technical asset storing the credential.",
		FalsePositives:             "Stored autorotated credentials with short lifetime can be considered a false positive after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        522,
	}
}

func (r longLivedCredentialOutsideOfVault) SupportedTags() []string {
	return []string{"credential", "credential-lifetime:unknown/hardcoded", "credential-lifetime:unlimited", "credential-lifetime:long", "credential-lifetime:short", "credential-lifetime:auto-rotation", "credential-lifetime:manual-rotation"}
}

func (r longLivedCredentialOutsideOfVault) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if technicalAsset.OutOfScope || technicalAsset.Technology == model.Vault {
			continue
		}
		storesCredential := false
		dataAtRisk := make([]string, 0)
		var exploitationImpact model.RiskExploitationImpact
		datas := technicalAsset.DataAssetsStoredSorted()
		exploitationImpact = model.MediumImpact
		exploitationProbability := model.Likely
		dataBreachProbability := model.Improbable
		for _, data := range datas {
			if data.IsTaggedWithAny(r.SupportedTags()...) {
				impact := model.MediumImpact
				breachProbability := model.Probable
				exploitProbability := model.Likely
				storesCredential = true
				dataAtRisk = append(dataAtRisk, data.Id)
				if data.IsTaggedWithAny("credential-lifetime:unknown/hardcoded", "credential-lifetime:unlimited") {
					impact = model.VeryHighImpact
					exploitProbability = model.VeryLikely
				} else if data.IsTaggedWithAny("credential-lifetime:long", "credential-lifetime:short") {
					impact = model.HighImpact
				}
				if data.IsTaggedWithAny("credential-lifetime:manual-rotation", "credential-lifetime:auto-rotation") && !data.IsTaggedWithAny("credential-lifetime:unknown/hardcoded") {
					impact = impact - 1
					breachProbability = model.Possible
				}
				if exploitationImpact <= impact {
					exploitationImpact = impact
				}
				if dataBreachProbability <= breachProbability {
					dataBreachProbability = breachProbability
				}
				if exploitationProbability <= exploitProbability {
					exploitationProbability = exploitProbability
				}
			}
		}
		if storesCredential {
			if technicalAsset.Confidentiality == model.StrictlyConfidential && technicalAsset.Encryption != model.NoneEncryption {
				exploitationProbability = exploitationProbability - 1
				dataBreachProbability = dataBreachProbability - 1
			}
			risks = append(risks, createRisk(technicalAsset, exploitationImpact, exploitationProbability, dataAtRisk, dataBreachProbability))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact, probability model.RiskExploitationLikelihood, dataAtRisk []string, dataProbability model.DataBreachProbability) model.Risk {
	title := "<b>Credential stored outside of vault</b> risk at <b>" + technicalAsset.Title + "</b>"
	risk := model.Risk{
		Category:                     CustomRiskRule.Category(),
		Severity:                     model.CalculateSeverity(probability, impact),
		ExploitationLikelihood:       probability,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        dataProbability,
		DataBreachTechnicalAssetIDs:  dataAtRisk,
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}

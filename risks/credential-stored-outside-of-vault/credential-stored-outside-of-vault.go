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
		Description:                "",
		Impact:                     "",
		ASVS:                       "v4.0.2-1.6.3 - Cryptographic Architectural Requirements, v4.0.2-6.4 - Secret Management",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#key-management, https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html#key-management-lifecycle-best-practices",
		Action:                     "",
		Mitigation:                 "",
		Check:                      "",
		Function:                   model.Operations,
		STRIDE:                     model.Repudiation,
		DetectionLogic:             "",
		RiskAssessment:             "",
		FalsePositives:             "None",
		ModelFailurePossibleReason: false,
		CWE:                        522,
	}
}

func (r longLivedCredentialOutsideOfVault) SupportedTags() []string {
	return []string{"credential", "credential-lifetime:unknown/unlimited/hardcoded", "credential-lifetime:long", "credential-lifetime:short", "credential-lifetime:auto-rotation", "credential-lifetime:manual-rotation"}
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
		var worstImpact model.RiskExploitationImpact
		datas := technicalAsset.DataAssetsStoredSorted()
		impact := model.LowImpact
		for _, data := range datas {
			if data.IsTaggedWithAny(r.SupportedTags()...) {
				storesCredential = true
				dataAtRisk = append(dataAtRisk, data.Id)
				if data.IsTaggedWithAny("credential-lifetime:unknown/unlimited/hardcoded") {
					impact = model.VeryHighImpact
				} else if data.IsTaggedWithAny("credential-lifetime:long") {
					impact = model.HighImpact
				} else if data.IsTaggedWithAny("credential-lifetime:short") {
					impact = model.MediumImpact
				}
				if data.IsTaggedWithAny("credential-lifetime:auto-rotation") {
					impact = model.LowImpact
				} else if data.IsTaggedWithAny("credential-lifetime:manual-rotation") {
					impact = impact - 1
				}
				if impact >= worstImpact {
					worstImpact = impact
				}
			}
		}
		if storesCredential {

			probability := model.VeryLikely
			dataProbability := model.Probable
			if technicalAsset.Confidentiality == model.Confidential {
				probability = model.Likely
				dataProbability = model.Possible
			} else if technicalAsset.Confidentiality == model.StrictlyConfidential {
				probability = model.Unlikely
				dataProbability = model.Improbable
			}
			risks = append(risks, createRisk(technicalAsset, worstImpact, probability, dataAtRisk, dataProbability))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact, probability model.RiskExploitationLikelihood, dataAtRisk []string, dataProbability model.DataBreachProbability) model.Risk {
	title := "<b>Missing audit log</b> risk at <b>" + technicalAsset.Title + "</b>"
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
package main

import (
	"github.com/threagile/threagile/model"
)

type runningAsPrivilegedUser string

var CustomRiskRule runningAsPrivilegedUser

func (r runningAsPrivilegedUser) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "running-as-privileged-user",
		Title:                      "Execution as Privileged User",
		Description:                "The asset is executing as a privileged user and not as a user with least privileges needed.",
		Impact:                     "A privileged user can bypass security functions among other things. If an asset running with high privileges is breached the attacker gains full control over the asset making further exploitation easier.",
		ASVS:                       "v4.0.3-1.2.1 - Use of unique or special low-privilege operating system accounts for all application components, services, and servers.",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html#enforce-least-privileges",
		Action:                     "Authorization",
		Mitigation:                 "Ensure that the principle of least privilege has been applied.",
		Check:                      "Referenced ASVS and cheat sheet",
		Function:                   model.Operations,
		STRIDE:                     model.ElevationOfPrivilege,
		DetectionLogic:             "Technical assets without any of the non-privileged supported tags or with any of the privileged tags are flagged.",
		RiskAssessment:             "Impact is based on criticality of the asset",
		FalsePositives:             "Running as root inside a container where the host remaps the user to a non-privileged one is a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        250,
	}
}

func (r runningAsPrivilegedUser) SupportedTags() []string {
	return []string{"root", "non-root", "privileged", "unprivileged", "isAdmin", "isNotAdmin"}
}

func (r runningAsPrivilegedUser) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, data := range model.DataAssetsTaggedWithAny(r.SupportedTags()...) {
		// credential-lifetime:unlimited set as default
		exploitationImpact := model.MediumImpact
		exploitationProbability := model.Frequent
		dataBreachProbability := model.Probable
		if data.IsTaggedWithAny("credential-lifetime:unknown/hardcoded") || !data.IsTaggedWithAny("credential-lifetime:unlimited", "credential-lifetime:long", "credential-lifetime:short") {
			// If only credential-tag is present, assume unknown
			exploitationImpact = model.HighImpact
		} else if data.IsTaggedWithAny("credential-lifetime:long") {
			exploitationProbability = model.VeryLikely
		} else if data.IsTaggedWithAny("credential-lifetime:short") {
			exploitationProbability = model.Likely
		}
		if data.IsTaggedWithAny("credential-lifetime:manual-rotation", "credential-lifetime:auto-rotation") && !data.IsTaggedWithAny("credential-lifetime:unknown/hardcoded") {
			exploitationImpact = exploitationImpact - 1
			exploitationProbability = exploitationProbability - 1
			dataBreachProbability = model.Possible
		}
		for _, technicalAsset := range data.StoredByTechnicalAssetsSorted() {
			if technicalAsset.OutOfScope || technicalAsset.Technology == model.Vault {
				continue
			}
			if technicalAsset.Confidentiality == model.StrictlyConfidential && technicalAsset.Encryption != model.NoneEncryption {
				// Assume that a technical asset classed for Strictly Confidential is well protected
				if exploitationProbability > model.Unlikely {
					exploitationProbability = exploitationProbability - 1
				}
				dataBreachProbability = model.Improbable
			}
			risks = append(risks, createRisk(technicalAsset, exploitationImpact, exploitationProbability, data.Id, dataBreachProbability))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact, probability model.RiskExploitationLikelihood, mostCriticalDataId string, dataProbability model.DataBreachProbability) model.Risk {
	title := "<b>Credential stored outside of vault</b> risk at <b>" + technicalAsset.Title + "</b>"
	risk := model.Risk{
		Category:                     CustomRiskRule.Category(),
		Severity:                     model.CalculateSeverity(probability, impact),
		ExploitationLikelihood:       probability,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		MostRelevantDataAssetId:      mostCriticalDataId,
		DataBreachProbability:        dataProbability,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}

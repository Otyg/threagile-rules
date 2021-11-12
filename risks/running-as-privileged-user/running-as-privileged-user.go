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
		DetectionLogic:             "Technical assets without any of the supported tags flagged.",
		RiskAssessment:             "Severity is based on the RAA of the asset",
		FalsePositives:             "Running as root inside a container where the host remaps the user to a non-privileged one is a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        250,
	}
}

func (r runningAsPrivilegedUser) SupportedTags() []string {
	return []string{"non-root", "unprivileged", "isNotAdmin"}
}

func (r runningAsPrivilegedUser) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		techAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if techAsset.OutOfScope {
			continue
		}
		if !techAsset.IsTaggedWithAny(CustomRiskRule.SupportedTags()...) {
			var impact = model.MediumImpact
			var likelihood = model.Likely
			if techAsset.RAA < 0.2 {
				impact = model.LowImpact
				likelihood = model.Unlikely
			} else if techAsset.RAA > 0.8 {
				impact = model.HighImpact
				likelihood = model.VeryLikely
			}
			risks = append(risks, createRisk(techAsset, impact, likelihood))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact, likelihood model.RiskExploitationLikelihood) model.Risk {
	title := "<b>Running as privileged user</b> risk at <b>" + technicalAsset.Title + "</b>"
	risk := model.Risk{
		Category:                     CustomRiskRule.Category(),
		Severity:                     model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachTechnicalAssetIDs:  []string{},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}

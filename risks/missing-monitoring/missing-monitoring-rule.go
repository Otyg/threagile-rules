package main

import (
	"github.com/threagile/threagile/model"
)

type missingMonitoringRule string

var CustomRiskRule missingMonitoringRule

func (r missingMonitoringRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "missing-monitoring",
		Title:                      "Missing Monitoring",
		Description:                "The model is missing a monitoring target for collecting, analysis and alerting on logdata and events.",
		Impact:                     "Without an external platform for monitoring an attacker might go undetected and might be able to tamper with logfiles etc.",
		ASVS:                       "v4.0.2-7 - Error Handling and Logging Verification Requirements",
		CheatSheet:                 "",
		Action:                     "Logging and monitoring",
		Mitigation:                 "Send logdata and other events to an external platform for storage and analysis.",
		Check:                      "Are relevant logs sent to an external monitoring platform?",
		Function:                   model.Architecture,
		STRIDE:                     model.Repudiation,
		DetectionLogic:             "Models without a Monitoring platform",
		RiskAssessment:             "The risk rating depends on the sensitivity of the technical assets and data processed.",
		FalsePositives:             "None",
		ModelFailurePossibleReason: true,
		CWE:                        778,
	}
}

func (r missingMonitoringRule) SupportedTags() []string {
	return []string{}
}

func (r missingMonitoringRule) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	hasMonitoring := false
	var mostRelevantAsset model.TechnicalAsset
	impact := model.MediumImpact
	probability := model.Likely
	for _, id := range model.SortedTechnicalAssetIDs() { // use the sorted one to always get the same tech asset with highest sensitivity as example asset
		techAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if techAsset.Technology == model.Monitoring {
			hasMonitoring = true
			break
		}
		if techAsset.HighestConfidentiality() == model.Confidential ||
			techAsset.HighestIntegrity() == model.Critical ||
			techAsset.HighestAvailability() == model.Critical {
			impact = model.HighImpact
			probability = model.VeryLikely
		} else if techAsset.HighestConfidentiality() == model.StrictlyConfidential ||
			techAsset.HighestIntegrity() == model.MissionCritical ||
			techAsset.HighestAvailability() == model.MissionCritical {
			impact = model.VeryHighImpact
			probability = model.VeryLikely
		}
		if techAsset.Confidentiality == model.Confidential ||
			techAsset.Integrity == model.Critical ||
			techAsset.Availability == model.Critical {
			impact = model.HighImpact
			probability = model.VeryLikely
		} else if techAsset.Confidentiality == model.StrictlyConfidential ||
			techAsset.Integrity == model.MissionCritical ||
			techAsset.Availability == model.MissionCritical {
			impact = model.VeryHighImpact
			probability = model.VeryLikely
		}
		// just for referencing the most interesting asset
		if techAsset.HighestSensitivityScore() > mostRelevantAsset.HighestSensitivityScore() {
			mostRelevantAsset = techAsset
		}
	}
	if !hasMonitoring {
		risks = append(risks, createRisk(mostRelevantAsset, impact, probability))
	} else {
		for _, id := range model.SortedTechnicalAssetIDs() { // use the sorted one to always get the same tech asset with highest sensitivity as example asset
			techAsset := model.ParsedModelRoot.TechnicalAssets[id]
			if techAsset.OutOfScope || techAsset.Technology == model.Monitoring {
				continue
			}
			targetMonitor := false
			impact := model.MediumImpact
			probability := model.Likely
			if techAsset.Confidentiality == model.Confidential ||
				techAsset.Integrity == model.Critical ||
				techAsset.Availability == model.Critical {
				impact = model.HighImpact
				probability = model.VeryLikely
			} else if techAsset.Confidentiality == model.StrictlyConfidential ||
				techAsset.Integrity == model.MissionCritical ||
				techAsset.Availability == model.MissionCritical {
				impact = model.VeryHighImpact
				probability = model.VeryLikely
			}
			commLinks := techAsset.CommunicationLinks
			for _, commLink := range commLinks {
				destination := model.ParsedModelRoot.TechnicalAssets[commLink.TargetId]
				if destination.Technology == model.Monitoring {
					targetMonitor = true
				}
			}
			if !targetMonitor {
				risks = append(risks, createRisk(techAsset, impact, probability))
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact, probability model.RiskExploitationLikelihood) model.Risk {
	title := "<b>Missing Monitoring (Logging platform)</b> in the threat model (referencing asset <b>" + technicalAsset.Title + "</b> as an example)"
	risk := model.Risk{
		Category:                     CustomRiskRule.Category(),
		Severity:                     model.CalculateSeverity(probability, impact),
		ExploitationLikelihood:       probability,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Improbable,
		DataBreachTechnicalAssetIDs:  []string{},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}

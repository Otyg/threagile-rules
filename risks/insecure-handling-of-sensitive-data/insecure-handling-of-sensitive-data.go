package main

import (
	"github.com/threagile/threagile/model"
)

type insecureHandlingOfSensitiveData string

var CustomRiskRule insecureHandlingOfSensitiveData

func (r insecureHandlingOfSensitiveData) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "insecure-handling-of-sensitive-data",
		Title:                      "Insecure Handling of Sensitive Data",
		Description:                "Sensitive data must be handled with care to avoid exposure. The processes handling the data must be sufficiently protected, this is especially important on assets storing sensitive data but even assets which only stores the data in memory must be protected.",
		Impact:                     "Sensitive data might be exposed if stored or processed by a component not sufficiently protected",
		ASVS:                       "v4.0.2-1.8 - Data Protection and Privacy Architectural Requirements, v4.0.2-8 - Data Protection Verification Requirements",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/IndexProactiveControls.html#8-protect-data-everywhere",
		Action:                     "Data protection",
		Mitigation:                 "Ensure all components has a confidentiality rating matching the data stored or processed",
		Check:                      "Referenced ASVS chapters, cheat sheet and CWE",
		Function:                   model.Architecture,
		STRIDE:                     model.InformationDisclosure,
		DetectionLogic:             "Data assets confidentiality rating is checked against the confidentiality rating of each technical asset storing or processing the data asset.",
		RiskAssessment:             "Impact is based on the classification of the data asset, likelihood and breach probability is based on classification of the technical asset and if the data is stored or processed",
		FalsePositives:             "Technical assets processing the data can be classed as false positives after individual review if the data is transient. Typical examples are reverse proxies and other network elements.",
		ModelFailurePossibleReason: true,
		CWE:                        200,
	}
}

func (r insecureHandlingOfSensitiveData) SupportedTags() []string {
	return []string{"PII"}
}

func (r insecureHandlingOfSensitiveData) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, technicalAsset := range model.SortedTechnicalAssetsByTitle() {
		if technicalAsset.Confidentiality == model.StrictlyConfidential || technicalAsset.OutOfScope {
			continue
		}
		var exploitationLikelihood model.RiskExploitationLikelihood
		var dataBreachProbability model.DataBreachProbability
		storedDataAssetsAtRisk := make(map[string]bool)
		switch technicalAsset.Confidentiality {
		case model.Confidential:
			exploitationLikelihood = model.Unlikely
			dataBreachProbability = model.Improbable
		case model.Restricted:
			exploitationLikelihood = model.Likely
			dataBreachProbability = model.Possible
		case model.Internal:
			exploitationLikelihood = model.VeryLikely
			dataBreachProbability = model.Possible
		default:
			exploitationLikelihood = model.Frequent
			dataBreachProbability = model.Probable
		}
		for _, dataAsset := range technicalAsset.DataAssetsStoredSorted() {
			if technicalAsset.Confidentiality < dataAsset.Confidentiality {
				var exploitationImpact model.RiskExploitationImpact
				switch dataAsset.Confidentiality {
				case model.Internal:
					exploitationImpact = model.LowImpact
				case model.Restricted:
					exploitationImpact = model.MediumImpact
				case model.Confidential:
					exploitationImpact = model.HighImpact
				case model.StrictlyConfidential:
					exploitationImpact = model.VeryHighImpact
				}
				storedDataAssetsAtRisk[dataAsset.Id] = true
				risks = append(risks, createRisk(dataAsset.Confidentiality, technicalAsset, exploitationImpact, exploitationLikelihood, dataAsset.Id, dataBreachProbability))
			}
		}
		for _, dataAsset := range technicalAsset.DataAssetsProcessedSorted() {
			_, alreadyAtRisk := storedDataAssetsAtRisk[dataAsset.Id]
			if !alreadyAtRisk && technicalAsset.Confidentiality < dataAsset.Confidentiality {
				var exploitationImpact model.RiskExploitationImpact
				switch dataAsset.Confidentiality {
				case model.Internal:
					exploitationImpact = model.LowImpact
				case model.Restricted:
					exploitationImpact = model.MediumImpact
				case model.Confidential:
					exploitationImpact = model.HighImpact
				case model.StrictlyConfidential:
					exploitationImpact = model.VeryHighImpact
				}
				if exploitationLikelihood > model.Unlikely {
					exploitationLikelihood = exploitationLikelihood - 1
				}
				if dataBreachProbability > model.Improbable {
					dataBreachProbability = dataBreachProbability - 1
				}
				risks = append(risks, createRisk(dataAsset.Confidentiality, technicalAsset, exploitationImpact, exploitationLikelihood, dataAsset.Id, dataBreachProbability))
			}
		}
	}
	return risks
}

func createRisk(class model.Confidentiality, technicalAsset model.TechnicalAsset, impact model.RiskExploitationImpact, probability model.RiskExploitationLikelihood, mostCriticalDataId string, dataProbability model.DataBreachProbability) model.Risk {
	title := "<b>Potential insecure handling of " + class.String() + " data</b> at <b>" + technicalAsset.Title + "</b>"
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
	risk.SyntheticId = risk.Category.Id + "@" + mostCriticalDataId + "@" + technicalAsset.Id
	return risk
}

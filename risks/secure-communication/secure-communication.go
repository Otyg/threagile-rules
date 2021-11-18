package main

import (
	"github.com/threagile/threagile/model"
)

type secureCommunication string

var CustomRiskRule secureCommunication

func (r secureCommunication) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "use-of-weak-cryptography-in-transit",
		Title:                      "Use Of Weak Cryptography in transit",
		Description:                "To ensure confidentiality during transit strong encryption must be used; weak, broken or soon to be deprecated algorithms must be avoided and recommended key lengths must be applied.",
		Impact:                     "Weak cryptography can result in information disclosure and a false sense of security.",
		ASVS:                       "v4.0.3-9.X - Communication",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
		Action:                     "Cryptography",
		Mitigation:                 "Ensure to use algoritms, modes and libraries that has been vetted and proven by industry and/or governments and follow recommendations and guidelines.",
		Check:                      "Referenced ASVS chapters and cheat sheets",
		Function:                   model.Operations,
		STRIDE:                     model.InformationDisclosure,
		DetectionLogic:             "Encrypted communication links",
		RiskAssessment:             "Risk is based on the confidentiality score of data sent or recieved.",
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
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		var mostCriticalCommlink model.CommunicationLink
		var hasEncryptedComLinks = false
		for _, comm := range technicalAsset.CommunicationLinksSorted() {
			if comm.Protocol.IsEncrypted() {
				hasEncryptedComLinks = true
				if comm.HighestConfidentiality() > mostCriticalCommlink.HighestConfidentiality() {
					mostCriticalCommlink = comm
				}
			}
		}
		if hasEncryptedComLinks {
			var mostCriticalDataAsset model.DataAsset
			for _, data := range append(mostCriticalCommlink.DataAssetsSentSorted(), mostCriticalCommlink.DataAssetsReceivedSorted()...) {
				if data.Confidentiality > mostCriticalDataAsset.Confidentiality {
					mostCriticalDataAsset = data
				}
			}
			var exploitationImpact model.RiskExploitationImpact
			switch mostCriticalDataAsset.Confidentiality {
			case model.Public:
				exploitationImpact = model.LowImpact
			case model.Internal:
				exploitationImpact = model.LowImpact
			case model.Restricted:
				exploitationImpact = model.MediumImpact
			case model.Confidential:
				exploitationImpact = model.HighImpact
			case model.StrictlyConfidential:
				exploitationImpact = model.VeryHighImpact
			}
			risks = append(risks, createRisk(technicalAsset, mostCriticalCommlink, mostCriticalDataAsset, exploitationImpact))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, commLink model.CommunicationLink, dataAsset model.DataAsset, exploitationImpact model.RiskExploitationImpact) model.Risk {
	title := "<b>Use of weak cryptography in transit</b> risk at <b>" + technicalAsset.Title + "</b>"
	risk := model.Risk{
		Category:                        CustomRiskRule.Category(),
		Severity:                        model.CalculateSeverity(model.Unlikely, exploitationImpact),
		ExploitationLikelihood:          model.Unlikely,
		ExploitationImpact:              exploitationImpact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: commLink.Id,
		MostRelevantDataAssetId:         dataAsset.Id,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
		DataBreachProbability:           model.Possible,
	}
	risk.SyntheticId = risk.Category.Id + "@" + commLink.Id
	return risk
}

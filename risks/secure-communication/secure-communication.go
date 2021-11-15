package main

import (
	"github.com/threagile/threagile/model"
)

type secureCommunication string

var CustomRiskRule secureCommunication

func (r secureCommunication) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "insecure-communication",
		Title:                      "Use Of Weak Cryptography in transit",
		Description:                "To ensure confidentiality during transit strong encryption must be used; weak, broken or soon to be deprecated algorithms must be avoided and recommended key lengths must be applied.",
		Impact:                     "Weak cryptography can result in information disclosure and a false sense of security.",
		ASVS:                       "v4.0.3-9.X - Communication",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
		Action:                     "Cryptography",
		Mitigation:                 "Stay current with recommended industry advice on secure configuration of TLS, or similar.",
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
	for _, comm := range model.CommunicationLinks {
		if comm.Protocol.IsEncrypted() {
			//TODO: Add logic for finding most critical data asset and base impact on that
			risks = append(risks, createRisk(model.ParsedModelRoot.TechnicalAssets[comm.SourceId], comm))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, commLink model.CommunicationLink) model.Risk {
	title := "<b>Use of weak cryptography</b> risk at <b>" + technicalAsset.Title + "</b>"
	risk := model.Risk{
		Category:                        CustomRiskRule.Category(),
		Severity:                        model.CalculateSeverity(model.Unlikely, model.MediumImpact),
		ExploitationLikelihood:          model.Unlikely,
		ExploitationImpact:              model.MediumImpact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: commLink.Id,
	}
	risk.SyntheticId = risk.Category.Id + "@" + commLink.Id
	return risk
}

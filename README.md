# Threagile Custom Rules
## Introduction
This is a set of custom Threagile rules I've created since I missed them among the built-in ones.
## The rules
### Missing Monitoring
This rule will check if there is a technical asset of the type `monitoring`. If no such asset exist the rule will create a risk. If there is a monitor, the rule will check all in scope technical assets to determine if there exist a data flow sending data to the monitor; if not the rule will creat a risk.
### Accidental Logging of Sensitive Data
If there is a dataflow from an asset storing or processing sensitive data (confidentialty rating `restricted` or higher or data assets tagged with `PII` or `credential`) to a technical asset of type `monitoring` this rule will create a risk to highlight the potential for leaking sensitive data into logfiles.
### Missing Audit log of Sensitive Asset
Any asset (technical or data) has a confidentiality rating of `restricted`, or higher, or a integrity rating of `Important`, or higher, this rule will create a risk. If the technical asset are sending data to a monitoring target the likelyhood will be set to `Unlikely` otherwise it will be set to `Very Likely`. 
The reason behind the scoring is that even if the asset is logged, it must be validated that there exist an auditlog for the sensitive data.
## Using
Clone the repo, build the image and run it as below.
```
docker run --rm -it -v "$(pwd)":/data threagile -custom-risk-rules-plugins accidental-logging-of-sensitive-data-rule.so,missing-monitoring-rule.so -verbose -model /data/threagile-example-model.yaml -output /data

```
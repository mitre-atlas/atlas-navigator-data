# ATLAS Navigator Data Changelog

## [1.10.0]() (2025-08-13)

- STIX and layers updated to use ATLAS Data 5.0.0 and ATT&CK 17.1

## [1.9.1]() (2025-08-13)

- STIX and layers updated to use ATLAS Data 4.9.1

## [1.9.0]() (2025-04-22)

- STIX and layers updated to use ATLAS Data 4.9.0

## [1.8.0]() (2025-03-14)

- STIX and layers updated to use ATLAS Data 4.8.0

## [1.7.0]() (2024-11-01)

- STIX and layers updated to use ATLAS Data 4.7.0, generative AI updates

## [1.6.4]() (2024-06-25)

- Added OpenCTI-compatible bundles for select case studies in `dist/opencti-bundles/`

## [1.6.3]() (2024-06-24)

- ATLAS STIX updated with ATT&CK Enterprise v15.1

## [1.6.2]() (2024-03-11)

- STIX and layers updated to use ATLAS Data 4.5.2, minor wording fixes

## [1.6.1]() (2024-01-12)

- ATLAS STIX (`stix-atlas-attack-enterprise.json`) updated with ATT&CK Enterprise v14.1
- STIX and layers updated to use ATLAS Data 4.5.1, minor mitigations/courses of action updates

## [1.6.0]() (2023-10-31)

- ATLAS STIX now includes mitigations as STIX courses of action
- Now generating ATLAS-only STIX as `stix-atlas.json`
  - ATLAS + ATT&CK Enterprise has been renamed to `stix-atlas-attack-enterprise.json`
- Updated to use ATLAS Data 4.5.0

## [1.5.1]() (2023-07-18)

Upgrade PyYAML to 6.0.1 to resolve install error - see https://github.com/yaml/pyyaml/issues/601.

## [1.5.0]() (2023-04-25)

- ATLAS STIX updated with ATT&CK Enterprise v13
- Updated to use ATLAS Data 4.4.0

## [1.4.0]() (2023-03-01)

- Updated to use ATLAS Data 4.3.0

## [1.3.0]() (2023-01-20)

- ATLAS STIX now also includes ATT&CK Enterprise v12 for comparison purposes
  - Any ATLAS techniques adapted from ATT&CK are additionally denoted with "(ATLAS)" to distinguish the names
- Updated to use ATLAS Data 4.2.0

## [1.2.0]() (2022-10-28)

- Updated ATLAS STIX and Navigator layer files for added technique and refreshed case studies
- Updated to use ATLAS Data 4.1.0

## [1.1.0]() (2022-06-09)

- Updated to use ATLAS Data 4.0.0, with support for outputting multiple `x-mitre-matrix` objects
- Outputs STIX 2.1 objects for [ATT&CK Workbench](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend) support
  - Import the outputted STIX as a new collection in the Workbench
- Supports ATT&CK Navigator 4.6.4

## [1.0.0]() (2022-03-23)

- Moved ATLAS Navigator scripts and docs into their own repository separate from [ATLAS Data](https://github.com/mitre-atlas/atlas-data)
- Updated to use ATLAS Data 3.0.0

# ATLAS Navigator Data Changelog

## [1.6.0]() (2023-10-31)

- ATLAS STIX now includes mitigations as STIX courses of action
- Now generating ATLAS-only STIX as `stix-atlas.json`
   + ATLAS + ATT&CK Enterprise has been renamed to `stix-atlas-attack-enterprise.json`
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
  + Any ATLAS techniques adapted from ATT&CK are additionally denoted with "(ATLAS)" to distinguish the names
- Updated to use ATLAS Data 4.2.0

## [1.2.0]() (2022-10-28)

- Updated ATLAS STIX and Navigator layer files for added technique and refreshed case studies
- Updated to use ATLAS Data 4.1.0

## [1.1.0]() (2022-06-09)

- Updated to use ATLAS Data 4.0.0, with support for outputting multiple `x-mitre-matrix` objects
- Outputs STIX 2.1 objects for [ATT&CK Workbench](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend) support
  + Import the outputted STIX as a new collection in the Workbench
- Supports ATT&CK Navigator 4.6.4

## [1.0.0]() (2022-03-23)

- Moved ATLAS Navigator scripts and docs into their own repository separate from [ATLAS Data](https://github.com/mitre-atlas/atlas-data)
- Updated to use ATLAS Data 3.0.0

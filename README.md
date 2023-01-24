# MITRE | ATLAS Navigator Data

[ATLAS Data](https://github.com/mitre-atlas/atlas-data) in STIX and [ATT&CK Navigator layer](https://github.com/mitre-attack/attack-navigator/tree/master/layers) formats for use with the [ATLAS Navigator](https://mitre-atlas.github.io/atlas-navigator/).

## Distributed files

Located the `dist` directory:

- `case-study-navigator-layers/`
    + Navigator layer files highlighting techniques used by each ATLAS case study.
    + View using the "Navigator Layer" > "View on ATLAS Navigator" sidebar buttons on each case study page accessible from https://atlas.mitre.org/studies.
- `default-navigator-layers/`
    + Navigator layer files highlighting the ATLAS matrix and a case study frequency heatmap.
    + Viewable by default on the [ATLAS Navigator](https://mitre-atlas.github.io/atlas-navigator/).
- `stix-atlas.json`
    + ATLAS matrix expressed as a STIX 2.1 bundle following the [ATT&CK data model](https://github.com/mitre/cti/blob/master/USAGE.md#the-attck-data-model).
        - Also includes ATT&CK Enterprise data
    + Used as domain data for the ATLAS Navigator.
    + Can also be imported into the [ATT&CK Workbench](https://github.com/center-for-threat-informed-defense/attack-workbench-frontend) as a collection.

## Development

Scripts in the `tools` directory update the files above.

### Installation

Ensure the `atlas-data` submodule is available by cloning this repository with `git clone --recurse-submodules` or running `git submodule update --init` on an existing repository.

Once the submodule is available, optionally run the following once to sparse checkout only the necessary files in the `atlas-data/dist` directory.
```bash
git -C atlas-data config core.sparseCheckout true
echo 'dist/*' >> .git/modules/atlas-data/info/sparse-checkout
git submodule update --force --checkout atlas-data
```

Install dependencies via `pip install -r tools/requirements.txt`

### Usage

When case studies update in `atlas-data`, run
```
python tools/generate_navigator_layer.py --layer case_study
```

When tactics and techniques update in `atlas-data`, run
```
python tools/generate_stix.py --include-attack
python tools/generate_navigator_layer.py --layer matrix
```
Omit the `--layer` option above to generate all outputs.

Run each script with `-h` for further options.

## Related work

ATLAS enables researchers to navigate the landscape of threats to artificial intelligence and machine learning systems.  Visit https://atlas.mitre.org for more information.

The ATLAS Navigator is a fork of the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

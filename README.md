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
- `stix-atlas-attack-enterprise.json`
    - The above ATLAS STIX 2.1 data combined with ATT&CK Enterprise data
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

## Export to Excel

ATLAS STIX data can be exported to Excel (.xslx) files through a modified version of [ATT&CK's STIX-to-Excel scripts](https://github.com/mitre-attack/mitreattack-python/tree/master/mitreattack/attackToExcel).

1. Clone [ATLAS' forked version of mitreattack-python](https://github.com/mitre-atlas/mitreattack-python.git) alongside this repository:
    ```
    git clone https://github.com/mitre-atlas/mitreattack-python.git mitreattack-python-atlas
    ```

2. Enter the new repository.
    ```
    cd mitreattack-python-atlas
    ```

3. Use Python 3.6+.  Set up a [virtual environment](https://docs.python.org/3/library/venv.html). For example:
    ```
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    ```


4. Install dependencies:
    ```
    pip install -r requirements-dev.txt
    ```

5. Run the `attackToExcel.py` script with the ATLAS STIX file.  The `domain` option is currently used as the output directory path. Run with `-h` to see full options.
    ```
    python <path_to_attackToExcel.py> -stix-file <path_to_atlas_stix_json> -domain <output_directory_path>
    ```
    For example, running from the `mitreattack-python-atlas` directory:
    ```
    python ./mitreattack/attackToExcel/attackToExcel.py -stix-file ../atlas-navigator-data/dist/stix-atlas.json -domain atlas-excel
    ```

6. See Excel (.xslx) files in `atlas-excel` or the specified output directory.


## Related work

ATLAS enables researchers to navigate the landscape of threats to artificial intelligence systems.  Visit https://atlas.mitre.org for more information.

The ATLAS Navigator is a fork of the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

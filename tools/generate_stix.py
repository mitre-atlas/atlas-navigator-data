from argparse import ArgumentParser
import json
from pathlib import Path

from stix2 import properties
from stix2.v20 import AttackPattern, Bundle, CustomObject, ExternalReference, KillChainPhase, Relationship
import yaml

"""
Custom MITRE ATT&CK STIX object to be able to use the Navigator.
        https://github.com/mitre/cti/blob/master/USAGE.md#the-attck-data-model
        https://stix2.readthedocs.io/en/latest/guide/custom.html?highlight=custom#Custom-STIX-Object-Types
"""
@CustomObject('x-mitre-tactic', [
    ('name', properties.StringProperty()),
    ('description', properties.StringProperty()),
    # https://github.com/oasis-open/cti-python-stix2/blob/master/stix2/properties.py#L197
    ('external_references', properties.ListProperty(ExternalReference)),
    ('x_mitre_shortname', properties.StringProperty()),
])
class AttackTactic():
    """Custom MITRE ATT&CK tactic STIX object."""
    def __init__(self, **kwargs):
        pass

@CustomObject('x-mitre-matrix', [
    ('name', properties.StringProperty()),
    ('description', properties.StringProperty()),
    # https://github.com/oasis-open/cti-python-stix2/blob/master/stix2/properties.py#L197
    ('external_references', properties.ListProperty(ExternalReference)),
    ('tactic_refs', properties.ListProperty(properties.StringProperty))
])
class AttackMatrix():
    """Custom MITRE ATT&CK matrix STIX object."""
    def __init__(self, **kwargs):
        pass


class ATLAS:
    """Converts from ATLAS YAML data to STIX."""
    # An lowercase, hyphened identifier for this data
    SOURCE_NAME = 'mitre-atlas'

    def __init__(self, atlas_data):
        """Initialize an ATLAS object.  Defaults provided via arguments in main.

        Args:
            atlas_data (str): Dictionary of ATLAS.yaml data
        """
        self.parse_data_files(atlas_data)
        # Track ATLAS tactics by short ID for matrix ordering lookup
        self.tactic_mapping = {}

    def parse_data_files(self, atlas_data):
        """Sets attributes from the ATLAS data."""

        self.matrix_id = atlas_data["id"]
        self.matrix_name = atlas_data["name"]
        self.matrix_version = atlas_data["version"]

        self.tactics = atlas_data["tactics"]
        self.techniques = atlas_data["techniques"]
        self.studies = atlas_data["case-studies"]

    def to_stix_json(self, stix_output_filepath, atlas_url):
        """Saves a STIX JSON file of the ATLAS tactics and techniques info.

        STIX Bundle specs
        https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_nuwp4rox8c7r
        """

        # Convert ATLAS techniques first to populate the referenced ATT&CK tactics
        # Only for parent techniques, as subtechniques do not have tactics references
        stix_techniques = []
        relationships = []
        parent_technique = None
        for t in self.techniques:
            if 'subtechnique-of' in t:
                pass
                # Create subtechnique and relationship
                subtechnique, relationship = self.subtechnique_to_attack_pattern(t, parent_technique, atlas_url)
                # Add to trackers
                stix_techniques.append(subtechnique)
                relationships.append(relationship)
            else:
                # Create and add this technique
                technique = self.technique_to_attack_pattern(t, atlas_url)
                stix_techniques.append(technique)
                # Save off reference to this technique for use by its subtechniques, should there be any following
                parent_technique = technique

        print(f'Converted {len(stix_techniques)} ATLAS techniques to STIX objects.')
        print(f'Created {len(relationships)} subtechnique relationships.')

        # Convert ATLAS tactics to x-mitre-tactics
        stix_tactics = [self.tactic_to_mitre_attack_tactic(t, atlas_url) for t in self.tactics]
        print(f'Converted {len(stix_tactics)} ATLAS tactics to STIX objects.')


        # Build x-mitre-matrix

        # Controls location of "View tactic/technique" on Navigator item right-click
        external_references = [
            ExternalReference(
                source_name = ATLAS.SOURCE_NAME,
                url=atlas_url,
                external_id = ATLAS.SOURCE_NAME # https://github.com/mitre-attack/attack-navigator/issues/362
            )
        ]

        # Build ordered list of tactics
        tactic_refs = []

        # Order of tactics in matrix, by STIX ID reference
        tactic_refs = [self.tactic_mapping[tactic['id']]['id'] for tactic in self.tactics]

        print(f'Generated {len(tactic_refs)} tactic references for the ATLAS matrix object.')

        stix_matrix_obj = AttackMatrix(
            name=f'{self.matrix_id} {self.matrix_version}',
            description=f'{self.matrix_name}: atlas.mitre.org',
            external_references=external_references,
            tactic_refs=tactic_refs
        )

        # JSON
        print('Bundling and serializing ATLAS data to JSON file...')
        bundle = Bundle(
            objects=stix_tactics + stix_techniques + relationships + [stix_matrix_obj],
            allow_custom=True # Needed as ATT&CK data has custom objects
        )
        stix_json = json.loads(bundle.serialize())

        # Save to file
        with open(stix_output_filepath, 'w') as f:
            json.dump(stix_json, f)
            print(f'Done! See {stix_output_filepath}\n')

    def referenced_tactics_to_kill_chain_phases(self, tactic_ids):
        """Converts a list of tactic IDs referenced by a technique
        to a list of STIX Kill Chain Phases.

        Kill Chain Phase spec:
        https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_i4tjv75ce50h
        """
        kill_chain_phases = []

        for tactic_id in tactic_ids:
            # Default properies, if not recognized as ATLAS
            kill_chain_name= '?'
            phase_name = '?'

            if tactic_id.startswith('AML.TA'):
                # ATLAS
                kill_chain_name = ATLAS.SOURCE_NAME # Using this as an identifier

                # Look up ATLAS tactic name
                tactic = next((tactic for tactic in self.tactics if tactic['id'] == tactic_id), None)
                # Ensure this is found
                assert(tactic is not None)
                # Convert name to lowercase and hyphens to fit spec
                phase_name = tactic['name'].lower().replace(' ', '-')

            # Create and add
            kcp = KillChainPhase(
                kill_chain_name=kill_chain_name,
                phase_name=phase_name
            )
            kill_chain_phases.append(kcp)

        return kill_chain_phases

    def build_atlas_external_references(self, t, atlas_url, route='techniques'):
        """Returns a STIX External Reference for ATLAS data."""

        # Construct the full URL to the resource
        url = atlas_url + '/' + route + '/' + t['id']

        # External references is a list
        return [
            ExternalReference(
                source_name=ATLAS.SOURCE_NAME, # The only required property
                url=url,
                external_id=t['id']
            )
        ]

    def tactic_to_mitre_attack_tactic(self, t, atlas_url):
        """Returns a STIX x-mitre-tactic representing this tactic."""
        at = AttackTactic(
            name=t['name'],
            description=t['description'],
            external_references=self.build_atlas_external_references(t, atlas_url, 'tactics'),
            x_mitre_shortname=t['name'].lower().replace(' ','-'),
        )

        # Track this tactic by short ID
        self.tactic_mapping[t['id']] = at

        return at

    def technique_to_attack_pattern(self, t, atlas_url):
        """Returns a STIX AttackPattern representing this technique."""
        return AttackPattern(
            name=t['name'],
            description=t['description'],
            kill_chain_phases=self.referenced_tactics_to_kill_chain_phases(t['tactics']),
            external_references=self.build_atlas_external_references(t, atlas_url),
            # Needed by Navigator else TypeError technique.platforms is not iterable
            allow_custom=True,
            x_mitre_platforms=['ATLAS']
        )

    def subtechnique_to_attack_pattern(self, t, parent, atlas_url):
        """Returns a STIX AttackPattern representing this subtechnique and a STIX Relationship
        between this subtechnique and its parent.

        https://github.com/mitre/cti/blob/master/USAGE.md#sub-techniques
        """
        subtechnique = AttackPattern(
            name=t['name'],
            description=t['description'],
            kill_chain_phases=parent.kill_chain_phases,
            external_references=self.build_atlas_external_references(t, atlas_url),
            # Needed by Navigator else TypeError technique.platforms is not iterable
            allow_custom=True,
            x_mitre_platforms=['ATLAS'],
            x_mitre_is_subtechnique=True
        )

        relationship = Relationship(
            source_ref=subtechnique.id,
            relationship_type='subtechnique-of',
            target_ref=parent.id
        )

        return subtechnique, relationship


if __name__ == '__main__':
    """Main entry point to STIX file generation for ATLAS data."""

    parser = ArgumentParser(
        description="Creates a STIX JSON file showing tactics and techniques used by ATLAS."
    )
    parser.add_argument("-f",
        type=str,
        dest="atlas_data_filepath",
        default="atlas-data/dist/ATLAS.yaml",
        help="Path to ATLAS.yaml file"
    )
    parser.add_argument("--url",
        type=str,
        dest="atlas_url",
        default="https://atlas.mitre.org",
        help="URL to ATLAS website for Navigator item linking"
    )
    parser.add_argument("-o",
        type=str,
        dest="output_dir",
        default="dist",
        help="Output directory for STIX JSON"
    )

    args = parser.parse_args()

    # Create output directories as needed
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    # Output filepath
    stix_output_filepath =  output_dir / 'stix-atlas.json'

    with open(args.atlas_data_filepath) as f:
        # Load in ATLAS data
        data = yaml.safe_load(f)

        # Initialize ATLAS-to-STIX structures
        atlas = ATLAS(data)

         # Convert to and save STIX
        atlas.to_stix_json(stix_output_filepath, args.atlas_url)

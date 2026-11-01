"""Preserve installed package licenses and inventory without local paths."""
import argparse
import importlib.metadata as metadata
import json
from pathlib import Path
import sys

PACKAGES = ('cryptography', 'zstandard', 'pycryptodome', 'psutil', 'pilk',
    'defusedxml', 'Pillow', 'cffi', 'pycparser', 'typing_extensions', 'pyinstaller')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    python_license=Path(sys.base_prefix)/'LICENSE.txt'
    if not python_license.is_file():
        raise FileNotFoundError('Python runtime license required')
    (args.out/'Python-LICENSE.txt').write_bytes(python_license.read_bytes())
    inventory = []
    for name in PACKAGES:
        distribution = metadata.distribution(name)
        record = dict(name=name, version=distribution.version,
            license=distribution.metadata.get('License-Expression') or distribution.metadata.get('License'),
            project_urls=distribution.metadata.get_all('Project-URL') or [], notices=[])
        for item in distribution.files or ():
            if (any(part.endswith('.dist-info') for part in item.parts) and
                    any(word in item.name.lower() for word in ('license','copying','notice'))):
                target = args.out / name / item.name
                if target.exists():
                    target = target.with_name(str(len(record['notices']))+'-'+item.name)
                target.parent.mkdir(exist_ok=True)
                target.write_bytes(distribution.locate_file(item).read_bytes())
                record['notices'].append(target.relative_to(args.out).as_posix())
        inventory.append(record)
    (args.out/'inventory.json').write_text(json.dumps(inventory,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'components':len(inventory),'notices':sum(len(x['notices']) for x in inventory)}))


if __name__ == '__main__':
    main()

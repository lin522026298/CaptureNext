"""Fetch exact unmodified GPL dependency sources from PyPI with SHA-256."""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.request import urlopen


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    args.out.mkdir(parents=True,exist_ok=False)
    records=[]
    for name,version in (('pilk','0.2.4'),('pyinstaller','6.22.3')):
        with urlopen('https://pypi.org/pypi/'+name+'/'+version+'/json',timeout=60) as response:
            metadata=json.load(response)
        sources=[item for item in metadata['urls'] if item['packagetype']=='sdist']
        if len(sources)!=1:raise ValueError('unique dependency source required')
        item=sources[0]
        target=args.out/item['filename']
        if target.parent!=args.out:raise ValueError('unsafe upstream filename')
        with urlopen(item['url'],timeout=60) as response,target.open('xb') as stream:
            digest=hashlib.sha256()
            for block in iter(lambda:response.read(1024*1024),b''):
                digest.update(block);stream.write(block)
        if digest.hexdigest()!=item['digests']['sha256']:raise ValueError('upstream source hash mismatch')
        records.append(dict(name=name,version=version,filename=item['filename'],bytes=target.stat().st_size,
            sha256=digest.hexdigest(),source_url=item['url'],modified=False))
    (args.out/'MANIFEST.json').write_text(json.dumps(dict(schema='capture-next-gpl-sources-1',
        files=records),indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'sources':len(records),'bytes':sum(x['bytes'] for x in records)}))


if __name__=='__main__':main()

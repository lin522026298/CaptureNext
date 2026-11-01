"""Read-only aggregate profiling of an explicit decoded cut and compact WUA.

No message bodies, names, IDs, paths from rows, URLs or keys in the report.
Matches are diagnostics, not authorization to assert a media association.
"""
import argparse
from collections import Counter,defaultdict
from contextlib import ExitStack,closing
import hashlib
import json
from pathlib import Path
import re

from defusedxml import ElementTree as ET
from wechat_capture_v2.common import digest_file,write_json_new
from .compact_archive import CompactArchive
from .union_archive import cold_input,cold_reader
from .union_delivery import _config


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('state','wua','out'):p.add_argument('--'+key,type=Path,required=True)
    a=p.parse_args(argv);config=_config(a.state);result=dict(scope='explicit_cold_cut_aggregate_only',association_accepted=False)
    with ExitStack() as stack:
        stack.enter_context(cold_input(a.state/'catalog.sqlite'));stack.enter_context(cold_input(a.wua))
        catalog=stack.enter_context(closing(cold_reader(a.state/'catalog.sqlite')))
        archive=stack.enter_context(CompactArchive(a.wua,readonly=True,immutable=True))
        checkpoints={r[0]:json.loads(r[1])['plaintext']['sha256'] for r in catalog.execute('''SELECT c.relative_path,d.evidence_json
            FROM checkpoint c JOIN db_capture d ON d.id=c.capture_id WHERE c.source_id=?''',(config['source_id'],))}
        def view(relative):
            path=a.state/'cache'/(hashlib.sha256(relative.encode()).hexdigest()+'.db')
            stack.enter_context(cold_input(path))
            if digest_file(path)!=checkpoints[relative]:raise ValueError('unaccepted auxiliary cut')
            return stack.enter_context(closing(cold_reader(path)))
        messages=defaultdict(set)
        for conv,server,logical in archive._db.execute('''SELECT o.conversation_id,o.server_id,l.logical_id
            FROM observation_record o JOIN source_snapshot s ON s.snapshot_id=o.snapshot_id
            JOIN message_link l ON l.observation_id=o.observation_id WHERE s.source_id=? AND o.account_alias=?
            AND (CAST(o.message_type AS INTEGER)&4294967295)=34''',(config['source_id'],config['account_alias'])):
            if conv and server and str(server)!='0':messages[(conv,str(server))].add(logical)
        voices=[]
        for relative in checkpoints:
            if not re.fullmatch(r'message/media_\d+\.db',relative):continue
            db=view(relative);names={r[0]:r[1] for r in db.execute('SELECT rowid,user_name FROM Name2Id')}
            counts=Counter();formats=Counter()
            for chat,server,blob in db.execute('SELECT chat_name_id,svr_id,voice_data FROM VoiceInfo'):
                counts['rows']+=1;key=(names.get(chat),str(server))
                if key[0]:counts['dictionary_mapped']+=1
                if server and len(messages.get(key,()))==1:counts['unique_logical_id_match']+=1
                elif len(messages.get(key,()))>1:counts['ambiguous_logical_id_match']+=1
                if isinstance(blob,bytes):
                    counts['blob_bytes']+=len(blob)
                    fmt=('silk_v3' if blob.startswith(b'#!SILK_V3') else 'silk_v3_prefixed' if blob.startswith(b'\x02#!SILK_V3')
                        else 'amr' if blob.startswith(b'#!AMR') else 'wave' if blob.startswith(b'RIFF') else 'other')
                    formats[fmt]+=1
            voices.append(dict(relative=relative,counts=dict(counts),formats=dict(formats)))
        result['voice']=voices
        xml=Counter();hashes=set()
        for row in archive._db.execute('''SELECT DISTINCT o.body_text FROM observation_record o
            JOIN source_snapshot s ON s.snapshot_id=o.snapshot_id WHERE s.source_id=? AND o.account_alias=?
            AND (CAST(o.message_type AS INTEGER)&4294967295) IN (3,43,47,49)''',(config['source_id'],config['account_alias'])):
            if row[0] is None:continue
            body=archive.pool.get_text(row[0]);start=body.find('<msg')
            if start<0:xml['no_msg_xml']+=1;continue
            if len(body)>4*1024*1024:xml['oversized_not_parsed']+=1;continue
            try:root=ET.fromstring(body[start:])
            except Exception:xml['parse_failed']+=1;continue
            for element in root.iter():
                tag=element.tag.rsplit('}',1)[-1]
                if tag not in ('img','voicemsg','videomsg','emoji','appattach','appmsg'):continue
                xml['tag:'+tag]+=1
                for key,value in element.attrib.items():
                    if key in ('md5','originsourcemd5','cdnthumbmd5','filemd5'):
                        xml['attribute:'+tag+':'+key]+=1
                        if re.fullmatch('[0-9a-fA-F]{32}',value):hashes.add(value.lower())
        result['xml']=dict(xml);result['xml_unique_md5_values']=len(hashes)
        if 'hardlink/hardlink.db' in checkpoints:
            db=view('hardlink/hardlink.db');hardlinks={};directory_shapes=Counter()
            for username, in db.execute('SELECT username FROM dir2id'):
                shape='hex32' if isinstance(username,str) and re.fullmatch('[0-9a-fA-F]{32}',username) else 'year_month' if isinstance(username,str) and re.fullmatch(r'\d{4}-\d{2}',username) else 'other'
                directory_shapes[shape]+=1
            for kind in ('image','video','file'):
                table=kind+'_hardlink_info_v4';counts=Counter()
                for md5,name,dir1,dir2 in db.execute('SELECT md5,file_name,dir1,dir2 FROM '+table):
                    counts['rows']+=1
                    if isinstance(md5,str) and md5.lower() in hashes:counts['xml_md5_equal']+=1
                    if isinstance(name,str) and any(token.lower() in hashes for token in re.findall('[0-9a-fA-F]{32}',name)):
                        counts['filename_has_xml_md5']+=1
                    counts['both_directory_ids_integer']+=int(type(dir1) is int and type(dir2) is int)
                hardlinks[kind]=dict(counts)
            result['hardlink']=dict(tables=hardlinks,directory_value_shapes=dict(directory_shapes))
    write_json_new(a.out,result);print(json.dumps(result))


if __name__=='__main__':main()

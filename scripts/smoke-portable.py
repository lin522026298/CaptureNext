"""Exercise the downloaded backend with only synthetic data, no desktop input.

Run with the source checkout's Python 3.11 environment. --app selects the
portable app directory; --out must be new. No account/login/key probe occurs.
"""
import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler

source_root=next(parent for parent in Path(__file__).resolve().parents if (parent/'wechat_capture_next').is_dir())
sys.path.insert(0,str(source_root))
from wechat_capture_next.tests import test_service as fixtures
from wechat_capture_v2.tests.test_backend import KEY, TABLE


class Host:
    def __init__(self, core, root, extra=()):
        self.stderr = (root / ('backend-'+str(time.time_ns())+'.private.stderr')).open('wb')
        self.process = subprocess.Popen([str(core),'--root',str(root),*extra],
            cwd=root,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.stderr,
            text=True,encoding='utf-8',creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        # A thread makes the first handshake deadline real, not a blocking
        # readline that could leave an acceptance run stuck indefinitely.
        import concurrent.futures
        pool=concurrent.futures.ThreadPoolExecutor(1)
        future=pool.submit(self.process.stdout.readline)
        try:
            boot=json.loads(future.result(timeout=90))
        except BaseException:
            self.process.stdin.close()
            self.process.wait(timeout=90)
            raise
        finally:
            pool.shutdown(wait=False)
        self.base,self.token=boot['url'],boot['token']
        self.mode=boot['mode']
        self.client=build_opener(ProxyHandler({}))

    def request(self,path,payload=None):
        headers={'X-Capture-Token':self.token,'Origin':self.base}
        if payload is not None:headers['Content-Type']='application/json'
        request=Request(self.base+path,data=json.dumps(payload).encode() if payload is not None else None,headers=headers)
        with self.client.open(request,timeout=15) as response:return json.load(response)

    def wait(self,predicate,seconds=90):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            if self.process.poll() is not None:raise RuntimeError('backend_exited')
            try:
                value=predicate()
                if value:return value
            except HTTPError as error:
                if error.code!=503:raise
            time.sleep(.1)
        raise TimeoutError('acceptance_deadline')

    def job(self,action,**values):
        submitted=self.request('/api/jobs',dict(action=action,**values))
        def complete():
            jobs=self.request('/api/jobs')['jobs']
            item=next((x for x in jobs if x['id']==submitted['id']),None)
            if not item or item['status'] in ('queued','running'):return None
            if item['status']!='completed':raise RuntimeError('job_failed_'+action)
            return item
        return self.wait(complete,180)

    def caught(self,count):
        def ready():
            state=self.request('/api/product')
            product=state.get('product',{})
            if (state.get('watch_error') or product.get('schedule_error')):
                raise RuntimeError('product_health_failed')
            return state if (state.get('watching') and state.get('summary',{}).get('active_messages')==count
                and product.get('union',{}).get('status')=='caught_up' and not state.get('busy')) else None
        return self.wait(ready)

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.write('quit\n');self.process.stdin.flush();self.process.stdin.close()
            self.process.wait(timeout=90)
        self.stderr.close()
        if self.process.returncode!=0:raise RuntimeError('backend_shutdown_failed')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    core=args.app.resolve()/'backend-dist'/'CaptureNextCore'/'CaptureNextCore.exe'
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    fixture=fixtures.ServiceTests('test_failed_capture_does_not_advance_checkpoint');fixture.setUp()
    host=None
    try:
        # The fixture's source, key and plaintext are generated during this
        # run. No data or credential from the host computer is selected.
        unused=fixture.init_service();unused.close()
        source_parent=fixture.source.parent
        keyring=fixture.keys
        attachment=b'CaptureNext synthetic attachment\x00\xff'
        attachment_sha=hashlib.sha256(attachment).hexdigest()
        (source_parent.parent/'synthetic-attachment.bin').write_bytes(attachment)
        source_before=hashlib.sha256(fixture.source.read_bytes()).hexdigest()
        command=[str(core),'--configure','--root',str(out),'--database-root',str(source_parent),
            '--keyring',str(keyring),'--account-alias','synthetic-account','--source-id','synthetic-computer','--self-username','self']
        configured=subprocess.run(command,cwd=out,capture_output=True,text=True,timeout=60,
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        (out/'configuration.private.stdout').write_text(configured.stdout,encoding='utf-8')
        (out/'configuration.private.stderr').write_text(configured.stderr,encoding='utf-8')
        assert configured.returncode==0, 'portable_configuration_failed'
        assert json.loads(configured.stdout)['configured']
        assert hashlib.sha256(fixture.source.read_bytes()).hexdigest()==source_before
        host=Host(core,out);assert host.mode!='recovery'
        host.caught(40)
        rows=host.request('/api/union-messages?limit=50')['rows'];assert len(rows)==40
        revised_id=next(row['logical_id'] for row in rows if row['body_text']=='synthetic 1')
        detail=host.request('/api/message-detail?id='+rows[0]['logical_id']);assert detail
        context=host.request('/api/message-context?id='+rows[0]['logical_id']);assert context['anchor']==rows[0]['logical_id']
        host.job('stop_watch')
        with closing(sqlite3.connect(fixture.plain)) as db,db:
            db.execute(f'UPDATE "{TABLE}" SET message_content=? WHERE local_id=1',('synthetic revised',))
            db.execute(f'INSERT INTO "{TABLE}" VALUES(-99,777,1,7,-999,?,NULL,NULL,-999)',('synthetic late backfill',))
        fixture.publish()
        host.job('start_watch');host.caught(41)
        host.job('stop_watch');host.close();host=None
        with closing(sqlite3.connect(fixture.plain)) as db,db:
            db.execute(f'INSERT INTO "{TABLE}" VALUES(-100,778,1,7,-1000,?,NULL,NULL,-1000)',('synthetic stopped collector catchup',))
        fixture.publish()
        host=Host(core,out);final_state=host.caught(42);host.job('stop_watch')
        retained=host.request('/api/message-detail?id='+revised_id)
        assert {'synthetic 1','synthetic revised'} <= {item['body_text'] for item in retained['observations']}
        assert retained['conflicts']
        current_rows=host.request('/api/union-messages?limit=50')['rows']
        late=next(row for row in current_rows if row['body_text']=='synthetic late backfill')
        late_detail=host.request('/api/message-detail?id='+late['logical_id'])
        assert any(item['raw_record']['local_id']==-99 and item['raw_record']['create_time']==-999
            for item in late_detail['observations'])
        assert any(row['body_text']=='synthetic stopped collector catchup' for row in current_rows)
        assert final_state['summary']['versions']==43
        assets=host.wait(lambda:host.request('/api/assets?limit=200'))['rows']
        assert any(row['file_sha']==attachment_sha and row['available_in_cas'] for row in assets)
        host.job('deep_verify')
        first=host.job('backup_pair',include_secrets=True)
        second=host.job('backup_pair',include_secrets=True)
        assert second['result']['reused_exact_authenticated_cut'] and second['result']['noop']
        keyed=host.job('restore_pair',snapshot_id=first['result']['snapshot_id'],name='restored-keyed')
        keyed_target=out/'archives'/'wechat-next'/'product'/'restored-keyed'
        assert keyed['result']['attachments_closed']
        assert (keyed_target/'state'/'90_SECRETS_PLAINTEXT_RESTRICTED'/'keyring.json').is_file()
        # The actual default is keyless, not a manually copied keyring later
        # removed to manufacture a keyless test.
        keyless=host.job('backup_pair')
        repeated=host.job('backup_pair')
        assert repeated['result']['reused_exact_authenticated_cut'] and repeated['result']['noop']
        restored=host.job('restore_pair',snapshot_id=keyless['result']['snapshot_id'],name='restored-keyless')
        assert restored['result']['attachments_closed']
        target=out/'archives'/'wechat-next'/'product'/'restored-keyless'
        assert not (target/'state'/'90_SECRETS_PLAINTEXT_RESTRICTED'/'keyring.json').exists()
        host.close();host=None
        host=Host(core,out,('--offline',str(target)));assert host.mode=='recovery'
        offline=host.wait(lambda:host.request('/api/union-messages?view=restored&limit=50'))['rows'];assert len(offline)==42
        observed=host.request('/api/message-detail?view=restored&id='+revised_id)['observations']
        assert {'synthetic 1','synthetic revised'} <= {item['body_text'] for item in observed}
        offline_assets=host.request('/api/assets?view=restored&limit=200')['rows']
        assert any(row['file_sha']==attachment_sha and row['available_in_cas'] for row in offline_assets)
        export=host.job('export_raw_asset',view='restored',sha=attachment_sha,name='restored-synthetic-attachment.bin')
        assert export['result']['export_readback_verified']
        exported=out/'archives'/'wechat-next'/'product-recovery'/'restored-synthetic-attachment.bin'
        assert exported.read_bytes()==attachment
        assert hashlib.sha256(exported.read_bytes()).hexdigest()==attachment_sha
        host.close();host=None
        result=dict(pass_=True,synthetic_only=True,initial_messages=40,final_messages=42,
            revised_messages=len({item['body_text'] for item in observed})-1,
            late_backfill=sum(row['body_text']=='synthetic late backfill' for row in offline),
            stopped_catchup=sum(row['body_text']=='synthetic stopped collector catchup' for row in offline),deep_verify=True,
            paired_restore=True,offline_view=True,no_change_backup_reused=True,
            default_keyless_restore=True,keyed_restore=True,restored_attachment_bytes_verified=True,
            native_desktop_input=False,real_wechat_access=False)
        (out/'RESULT.private.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(result))
    finally:
        if host is not None:host.close()
        fixture.tearDown()


if __name__=='__main__':main()

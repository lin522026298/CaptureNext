"""Compile and exercise the real tray's pure C# projection; never start a UI/core."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class DesktopTrayStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler=Path(os.environ.get('WINDIR','C:/Windows'))/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
        if not compiler.is_file():
            raise unittest.SkipTest('Windows .NET compiler unavailable')
        cls.temporary=tempfile.TemporaryDirectory(prefix='capture-tray-status-')
        cls.addClassCleanup(cls.temporary.cleanup)
        root=Path(cls.temporary.name)
        source=(Path(__file__).parents[1]/'desktop/CaptureNext.cs').read_text(encoding='utf-8')
        projection=source[source.index('    class TrayStatus {'):source.index('    class Shell :')]
        harness='''
using System;
using System.Collections.Generic;
using System.Text;
using System.Web.Script.Serialization;
namespace CaptureNext {
PROJECTION
class Test {
    static void Main() {
        var json=new JavaScriptSerializer();
        var notices=new TrayNotice();
        string line;
        while((line=Console.ReadLine())!=null) {
            var input=json.Deserialize<Dictionary<string,object>>(line);
            var state=(Dictionary<string,object>)input["state"];
            var status=TrayStatus.From(state);
            Console.WriteLine(json.Serialize(new {items=status.Items,issues=status.Issues,
                text=status.Text("本地聊天档案 · 自动归档中"),
                notify=notices.Changed(status.FaultKey,(bool)input["enabled"])}));
        }
    }
}}
'''.replace('PROJECTION',projection)
        target=root/'TrayStatusTest.cs'
        target.write_text(harness,encoding='utf-8')
        cls.executable=root/'TrayStatusTest.exe'
        result=subprocess.run([str(compiler),'/nologo','/target:exe','/r:System.Web.Extensions.dll',
            '/out:'+str(cls.executable),str(target)],capture_output=True,text=True)
        if result.returncode:
            raise AssertionError(result.stdout+result.stderr)

    def state(self,**pipelines):
        return dict(watching=True,busy=False,closing=False,watch_error=None,
            product=dict(mode='normal',union=dict(status='caught_up'),schedule_error=None,
                pipelines=pipelines))

    def project(self,*states,enabled=True):
        inputs=[dict(state=state,enabled=enabled) if not isinstance(state,tuple)
            else dict(state=state[0],enabled=state[1]) for state in states]
        result=subprocess.run([str(self.executable)],input=''.join(json.dumps(row)+'\n' for row in inputs),
            capture_output=True,text=True,encoding='utf-8')
        self.assertEqual(result.returncode,0,result.stderr)
        return [json.loads(line) for line in result.stdout.splitlines()]

    def test_normal_has_no_alert_and_does_not_claim_unrun_backups_succeeded(self):
        value=self.project(self.state())[0]
        self.assertFalse(value['notify']);self.assertFalse(value['issues'])
        self.assertIn('备份：尚无结果',value['items'])

    def test_schedule_ledger_failure_reaches_tray(self):
        state=self.state();state['product']['schedule_error']='OSError'
        value=self.project(state)[0]
        self.assertIn('计划账本失败',value['text']);self.assertTrue(value['notify'])

    def test_each_critical_pipeline_failure_is_visible(self):
        for stage,label in [('backup','备份'),('deep_verify','深度校验'),('restore','恢复')]:
            with self.subTest(stage=stage):
                value=self.project(self.state(**{stage:dict(outcome='failed',reason='OSError',last_success='earlier')}))[0]
                self.assertIn(label+'失败',value['issues']);self.assertTrue(value['notify'])

    def test_aggregate_retains_all_failure_components_and_safe_tooltip_limit(self):
        value=self.project(self.state(**{stage:dict(outcome='failed') for stage in
            ['backup','deep_verify','restore','capture','union','identities','media_voice','media','media_cache']}))[0]
        self.assertIn('备份：失败',value['items']);self.assertIn('恢复：失败',value['items'])
        self.assertIn('深度校验：失败',value['items']);self.assertLessEqual(len(value['text']),63)

    def test_completed_backup_with_gc_pending_is_not_backup_failure(self):
        for cleanup in [dict(backup_cleanup=dict(outcome='warning',details=dict(cleanup_pending=True))),{}]:
            state=self.state(backup=dict(outcome='completed',details=dict(governance=dict(cleanup_pending=True))),**cleanup)
            value=self.project(state)[0]
            self.assertIn('备份：已完成',value['items'])
            self.assertIn('备份整理待完成',value['issues']);self.assertNotIn('备份失败',value['issues'])
            self.assertNotIn('备份待处理',value['issues'])

    def test_pending_and_interrupted_are_actionable_but_running_is_not(self):
        for outcome in ['warning','pending','partial','interrupted_unconfirmed','interrupted']:
            value=self.project(self.state(restore=dict(outcome=outcome)))[0]
            self.assertIn('恢复待处理',value['issues'])
        for outcome in ['running','queued','completed']:
            value=self.project(self.state(restore=dict(outcome=outcome,pending=outcome!='completed')))[0]
            self.assertFalse(value['issues']);self.assertFalse(value['notify'])

    def test_repeated_fault_and_timestamp_changes_notify_only_once(self):
        first=self.state(backup=dict(outcome='failed',reason='OSError',last_attempt='one',last_success='old'))
        later=self.state(backup=dict(outcome='failed',reason='OSError',last_attempt='two',last_success='new'))
        changed=self.state(backup=dict(outcome='failed',reason='ValueError'))
        values=self.project(first,first,later,changed,changed)
        self.assertEqual([value['notify'] for value in values],[True,False,False,True,False])

    def test_disabled_notifications_are_silent_and_not_replayed_on_enable(self):
        state=self.state(backup=dict(outcome='failed'))
        values=self.project((state,False),(state,False),(state,True),
            (self.state(backup=dict(outcome='failed',reason='different')),True))
        self.assertEqual([value['notify'] for value in values],[False,False,False,True])

    def test_success_resets_fault_and_same_failure_can_notify_when_it_recurs(self):
        failure=self.state(deep_verify=dict(outcome='failed'))
        values=self.project(failure,self.state(deep_verify=dict(outcome='completed')),failure)
        self.assertEqual([value['notify'] for value in values],[True,False,True])

    def test_raw_failure_payload_never_enters_menu_or_tooltip(self):
        secret='SYNTHETIC_PRIVATE_TEXT_C:/example/private'
        state=self.state(backup=dict(outcome='failed',reason=secret,error_type=secret,next_step=secret))
        state['watch_error']=secret;state['product']['schedule_error']=secret
        value=self.project(state)[0]
        self.assertNotIn(secret,json.dumps(value));self.assertTrue(value['notify'])

    def test_recovery_is_not_reported_as_capture_failure(self):
        state=self.state();state.update(watching=False)
        state['product'].update(mode='recovery',union=dict(status='unavailable'))
        value=self.project(state)[0]
        self.assertFalse(value['issues']);self.assertIn('自动归档：只读恢复模式',value['items'])

    def test_existing_watch_close_and_union_attention_are_preserved(self):
        state=self.state();state['watch_error']='OSError'
        self.assertIn('自动归档失败',self.project(state)[0]['issues'])
        state['watch_error']=None;state['closing']=True
        self.assertIn('自动归档已停止',self.project(state)[0]['issues'])
        state['closing']=False;state['product']['union']['status']='pending'
        self.assertIn('联合同步待完成',self.project(state)[0]['issues'])

    def test_poll_wiring_is_nonactivating_and_respects_notification_setting(self):
        source=(Path(__file__).parents[1]/'desktop/CaptureNext.cs').read_text(encoding='utf-8')
        poll=source[source.index('        async Task Poll()'):source.index('        void ApplyStartup(')]
        self.assertIn('notifications=(bool)settings["notifications"]',poll)
        self.assertIn('UpdateHealth(TrayStatus.From(state),ordinary)',poll)
        self.assertNotIn('OpenWindow(',poll);self.assertNotIn('MessageBox.',poll)
        alert=source[source.index('        void Alert('):source.index('        void UpdateHealth(')]
        self.assertIn('if(!notifications) return;',alert)
        self.assertIn('tray.ShowBalloonTip(',alert)


if __name__=='__main__':unittest.main()

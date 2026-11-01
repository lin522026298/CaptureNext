"""Owned synthetic-only, real headless browser QA; never accepts a live state."""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sqlite3
import threading
import time
import traceback
from unittest.mock import patch

from playwright.sync_api import sync_playwright, expect

from wechat_capture_next.console import create_server
from wechat_capture_next.tests.test_service import ServiceTests
from wechat_capture_v2.tests.test_backend import make_plain, TABLE
from wechat_capture_v2.tests.test_integration import reserve80
from wua.store import ArchiveStore
from tests.test_wua_store import observation


def main():
    project = Path(__file__).resolve().parents[2]
    root = project/'working'/'wechat_capture_next_20261020'/'ui-qa'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    root.mkdir(parents=True)
    fixture = ServiceTests()
    fixture.root = root/'fixture'
    fixture.root.mkdir()
    fixture.plain = fixture.root/'plain.db'
    make_plain(fixture.plain, count=123)
    with closing(sqlite3.connect(fixture.plain)) as db, db:
        db.execute(f'UPDATE "{TABLE}" SET create_time=1700000000+local_id')
        db.execute(f'UPDATE "{TABLE}" SET message_content=? WHERE local_id=123', ('QA needle <img src=x onerror=alert(1)> '+'longsynthetic'*1200,))
    reserve80(fixture.plain)
    fixture.source = fixture.root/'encrypted.db'
    fixture.publish()
    with closing(fixture.init_service()) as service:
        service.capture(force=True)
        state = service.state
    media = fixture.source.parent.parent/'media'
    media.mkdir()
    for i in range(53):
        (media/f'synthetic-attachment-{i:03}.txt').write_text(f'SYNTHETIC ONLY {i}', encoding='utf-8')
    server = create_server(state, root/'outputs', interval=.1, reconcile_seconds=300)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval':.05}, daemon=True)
    thread.start()
    report = {'scope':'synthetic-only next UI', 'artifact_root':str(root), 'checks':[], 'browser_errors':[], 'requests':[], 'url':server.base_url}
    (root/'runtime.json').write_text(json.dumps({'url':server.base_url},ensure_ascii=False),encoding='utf-8')

    def record(name, passed, detail=None):
        report['checks'].append(dict(name=name, passed=bool(passed), detail=detail))

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={'width':1440,'height':1000}, locale='zh-CN', timezone_id='Asia/Shanghai')
            page = context.new_page()
            page.on('pageerror', lambda e:report['browser_errors'].append(str(e)))
            page.on('request', lambda r:report['requests'].append(r.url.split('?')[0]))
            try:
                page.goto(server.base_url)
                expect(page.locator('#connection-label')).to_have_text('本地服务已连接')
                (root/'initial-accessibility.txt').write_text(page.locator('body').aria_snapshot(),encoding='utf-8')
                routes = ['overview','messages','assets','backups','compare','jobs']
                for width in [320,768,1440,3840]:
                    page.set_viewport_size({'width':width,'height':1000 if width<3840 else 2160})
                    for route in routes:
                        page.locator(f'.nav-link[href="#{route}"]').click()
                        expect(page.locator(f'#{route}')).to_be_visible()
                        page.wait_for_timeout(150)
                        dimensions = page.evaluate('({viewport:innerWidth,scroll:document.documentElement.scrollWidth})')
                        record(f'layout {width} {route}', dimensions['scroll']<=width, dimensions)
                        if route=='messages':
                            search=page.locator('#message-search button').evaluate('(el)=>({whiteSpace:getComputedStyle(el).whiteSpace,height:el.getBoundingClientRect().height})')
                            record(f'search action single line {width}',search['whiteSpace']=='nowrap' and search['height']<=48,search)
                        page.evaluate('window.scrollTo(0,0)')
                        page.screenshot(path=str(root/f'{width}-{route}.png'),full_page=True)
                page.set_viewport_size({'width':1440,'height':1000})
                page.locator('.nav-link[href="#messages"]').click()
                expect(page.locator('.message-row')).to_have_count(50)
                record('first page 50',True)
                shown_time=page.locator('.message-meta time').first.inner_text()
                record('epoch timestamp year 2023', '2023' in shown_time, shown_time)
                page.locator('#message-next').click()
                expect(page.locator('#message-page')).to_have_text('第 2 页')
                page.locator('#message-next').click()
                expect(page.locator('.message-row')).to_have_count(23)
                record('message pagination 50/50/23',True)
                page.locator('#message-query').fill('QA needle')
                page.locator('#message-search button').click()
                expect(page.locator('.message-row')).to_have_count(1)
                record('search returns exact synthetic match',True)
                record('body renders markup as text',page.locator('.message-body img').count()==0 and '<img' in page.locator('.message-body').inner_text())
                page.locator('#message-query').fill('not-present-synthetic-only')
                page.locator('#message-search button').click()
                expect(page.locator('#message-results')).to_contain_text('没有匹配')
                record('empty search',True)
                page.route('**/api/messages?*',lambda route:route.fulfill(status=503,json={'error':'synthetic temporary failure'}))
                page.locator('#message-query').fill('error-fixture')
                page.locator('#message-search button').click()
                expect(page.locator('#message-results')).to_contain_text('消息加载失败')
                record('message error handled',True)
                page.screenshot(path=str(root/'message-error.png'),full_page=True)
                page.unroute('**/api/messages?*')
                page.locator('.nav-link[href="#backups"]').click()
                page.locator('.skip-link').focus()
                page.keyboard.press('Enter')
                record('skip preserves current page',page.url.endswith('#backups'),page.url)

                def submit(control):
                    with page.expect_response(lambda r:r.url.endswith('/api/jobs') and r.request.method=='POST') as response:
                        control.click()
                    data=response.value.json()
                    if response.value.status!=202:
                        raise AssertionError(data)
                    ident=data['id']
                    page.locator('.nav-link[href="#jobs"]').click()
                    row=page.locator(f'[data-job-id="{ident}"]')
                    expect(row.locator('.job-badge')).not_to_have_text('排队中',timeout=30000)
                    expect(row.locator('.job-badge')).not_to_have_text('执行中',timeout=30000)
                    return row,ident

                page.locator('.nav-link[href="#overview"]').click()
                row,_=submit(page.locator('[data-action="capture"]'))
                record('manual capture job', '已完成' in row.inner_text(),row.inner_text()[:500])
                page.locator('.nav-link[href="#overview"]').click()
                row,_=submit(page.locator('[data-action="verify"]'))
                record('object verification job', '已完成' in row.inner_text(),row.inner_text()[:500])
                # Poll refresh must not remove keyboard focus from results disclosure.
                detail=row.locator('summary')
                detail.focus()
                page.wait_for_timeout(3400)
                record('job disclosure focus survives poll',page.evaluate('document.activeElement.tagName')=='SUMMARY')
                page.locator('.nav-link[href="#assets"]').click()
                page.locator('#assets-root').fill(str(media))
                row,_=submit(page.locator('#assets-configure button'))
                record('configure synthetic attachments', '已完成' in row.inner_text(),row.inner_text()[:250])
                page.locator('.nav-link[href="#overview"]').click()
                row,_=submit(page.locator('[data-action="capture"]'))
                record('capture synthetic attachments', '已完成' in row.inner_text(),row.inner_text()[:250])
                page.locator('.nav-link[href="#assets"]').click()
                expect(page.locator('.file-row')).to_have_count(50)
                page.locator('#asset-next').click()
                expect(page.locator('.file-row')).to_have_count(3)
                record('asset pagination 50/3',True)
                page.screenshot(path=str(root/'populated-assets.png'),full_page=True)
                page.locator('.file-row button').first.click()
                expect(page.locator('#export-dialog')).to_be_visible()
                record('export dialog accessible name', bool(page.locator('#export-dialog').get_attribute('aria-labelledby') or page.locator('#export-dialog').get_attribute('aria-label')))
                page.screenshot(path=str(root/'attachment-export-dialog.png'))
                page.keyboard.press('Escape')
                expect(page.locator('#export-dialog')).not_to_be_visible()
                record('export escape closes without submit',True)
                page.locator('.file-row button').first.click()
                page.locator('#export-name').fill('qa-export.txt')
                row,_=submit(page.locator('#asset-export button[type="submit"]'))
                record('asset export job', '已完成' in row.inner_text(),row.inner_text()[:250])
                page.locator('.nav-link[href="#backups"]').click()
                page.locator('#backup-name').fill('uiqa')
                row,_=submit(page.locator('#backup-create button'))
                record('backup job', '已完成' in row.inner_text(),row.inner_text()[:500])
                page.locator('.nav-link[href="#backups"]').click()
                expect(page.locator('#restore-snapshot option')).to_have_count(2)
                page.locator('#restore-snapshot').select_option(index=1)
                page.locator('#restore-name').fill('qa-restored')
                page.locator('#restore-confirm').check()
                row,_=submit(page.locator('#backup-restore button'))
                record('restore job', '已完成' in row.inner_text(),row.inner_text()[:500])
                page.locator('.nav-link[href="#compare"]').click()
                row,_=submit(page.locator('[data-action="validate"]'))
                record('independent same-cut validation job', '已完成' in row.inner_text(),row.inner_text()[:500])
                page.locator('.nav-link[href="#compare"]').click()
                row,_=submit(page.locator('[data-action="sync_wua"]'))
                record('managed WUA sync job', '已完成' in row.inner_text(),row.inner_text()[:500])
                reference=root/'reference'/'synthetic-cold-reference.wua.sqlite'
                reference.parent.mkdir()
                shutil.copy2(root/'outputs'/'managed-wua'/'archive.wua.sqlite',reference)
                page.locator('.nav-link[href="#compare"]').click()
                page.locator('#compare-reference').fill(str(reference))
                page.locator('#compare-name').fill('qa-comparison')
                row,_=submit(page.locator('#compare-form button'))
                record('cold synthetic reference comparison', '已完成' in row.inner_text(),row.inner_text()[:500])
                mismatched=root/'reference'/'different.wua.sqlite'
                with ArchiveStore(mismatched) as archive:
                    archive.import_observations({'source_id':'synthetic-other'}, {'source_id':'synthetic-other','snapshot_id':'synthetic-different'}, [observation(native_locator=1,body_text='SYNTHETIC DIFFERENT REFERENCE')])
                page.locator('.nav-link[href="#compare"]').click()
                page.locator('#compare-reference').fill(str(mismatched))
                page.locator('#compare-name').fill('qa-difference')
                row,_=submit(page.locator('#compare-form button'))
                record('comparison differences not called passed', '需核对' in row.inner_text(),row.inner_text()[:500])
                page.screenshot(path=str(root/'comparison-warning.png'),full_page=True)
                page.locator('.nav-link[href="#backups"]').click()
                page.locator('#restore-snapshot').select_option(index=1)
                page.locator('#restore-name').fill('qa-restored')
                page.locator('#backup-restore button').click()
                expect(page.locator('.toast.error')).to_be_visible()
                record('existing restore target rejected',True)
                page.locator('.nav-link[href="#overview"]').click()
                row,_=submit(page.locator('#watch-toggle'))
                record('watch start synthetic source', '已完成' in row.inner_text())
                page.locator('.nav-link[href="#overview"]').click()
                expect(page.locator('#watch-toggle')).to_have_text('停止实时采集',timeout=10000)
                row,_=submit(page.locator('#watch-toggle'))
                record('watch stop synthetic source', '已完成' in row.inner_text())
                context.set_offline(True)
                expect(page.locator('#connection-label')).to_have_text('本地服务未连接',timeout=24000)
                page.locator('.nav-link[href="#overview"]').click()
                record('offline mutating controls disabled',page.locator('#watch-toggle').is_disabled() and page.locator('[data-action="capture"]').is_disabled())
                context.set_offline(False)
                page.locator('#retry-connection').click()
                expect(page.locator('#connection-label')).to_have_text('本地服务已连接')
                record('connection recovers',True)
                # Real synthetic source failure, not a mocked success banner.
                page.locator('.nav-link[href="#overview"]').click()
                row,_=submit(page.locator('#watch-toggle'))
                paused=fixture.source.with_suffix('.temporarily-offline')
                fixture.source.rename(paused)
                try:
                    page.locator('.nav-link[href="#overview"]').click()
                    expect(page.locator('#capture-state')).to_contain_text('错误',timeout=20000)
                    record('watch source error not called healthy',True)
                finally:
                    paused.rename(fixture.source)
                expect(page.locator('#capture-state')).to_have_text('实时采集已启用',timeout=20000)
                row,_=submit(page.locator('#watch-toggle'))
                record('synthetic source recovery', '已完成' in row.inner_text())
                # Real worker statistics failure while paused, not a routed
                # fake 503. Restore the reader, then recover ONLY via the
                # actual browser retry button/HTTP task submission.
                with patch.object(server.coordinator, '_read_summary',
                                  side_effect=sqlite3.OperationalError('synthetic statistics failure')):
                    server.coordinator.submit({'action':'verify','request_id':'uiqa_statistics_failure'})
                    end=time.monotonic()+15
                    while time.monotonic()<end:
                        snapshot=server.coordinator.control_snapshot()
                        if not snapshot['summary_valid'] and not snapshot['busy']:
                            break
                        time.sleep(.05)
                    else:
                        raise AssertionError('statistics failure was not reached at a paused boundary')
                    expect(page.locator('#connection-label')).to_have_text('本地服务未连接',timeout=24000)
                    record('paused statistics failure not called healthy',
                           page.locator('#watch-toggle').is_disabled())
                with page.expect_response(lambda r:r.url.endswith('/api/jobs') and r.request.method=='POST') as recovered:
                    page.locator('#retry-connection').click()
                response=recovered.value
                record('retry button submits only read-only statistics job',
                       response.status==202 and response.request.post_data_json.get('action')=='refresh_status')
                expect(page.locator('#connection-label')).to_have_text('本地服务已连接',timeout=24000)
                snapshot=server.coordinator.control_snapshot()
                record('paused statistics recovers through real UI',
                       snapshot['summary_valid'] and not snapshot['watching'])
                page.route('**/api/messages?*',lambda route:route.fulfill(json={'rows':[],'total':0,'next_offset':None}))
                page.locator('.nav-link[href="#messages"]').click()
                page.locator('#message-query').fill('')
                page.locator('#message-search button').click()
                expect(page.locator('#message-results')).to_contain_text('归档中暂无可浏览消息')
                record('empty archive UI state',True)
                page.screenshot(path=str(root/'empty-archive.png'),full_page=True)
                page.unroute('**/api/messages?*')
                page.locator('.nav-link[href="#overview"]').click()
                record('no external requests',all(url.startswith(server.base_url) for url in report['requests']))
                record('no browser runtime errors',not report['browser_errors'],report['browser_errors'])
                unnamed=page.evaluate('''() => Array.from(document.querySelectorAll('input,select')).filter(e=>!e.labels?.length&&!e.getAttribute('aria-label')&&!e.getAttribute('aria-labelledby')).map(e=>e.id)''')
                record('all form controls labelled',not unnamed,unnamed)
                page.screenshot(path=str(root/'final-overview.png'),full_page=True)
            except Exception:
                report['exception']=traceback.format_exc()
                page.screenshot(path=str(root/'failure.png'),full_page=True)
            finally:
                context.close()
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
        report['server_stopped']=not thread.is_alive() and not server.coordinator.thread.is_alive()
        report['jobs_snapshot']=server.coordinator.jobs_snapshot()
        report['pass_all']=bool(report['checks']) and not report.get('exception') and all(c['passed'] for c in report['checks']) and report['server_stopped']
        (root/'REPORT.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps({'report':str(root/'REPORT.json'),'passed':sum(c['passed'] for c in report['checks']), 'failed':[c for c in report['checks'] if not c['passed']], 'exception':report.get('exception'), 'server_stopped':report['server_stopped']},ensure_ascii=False))
    if not report['pass_all']:
        raise SystemExit(1)


if __name__=='__main__':
    main()

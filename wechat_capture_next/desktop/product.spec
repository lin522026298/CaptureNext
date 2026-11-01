# Source modules are intentionally shipped as .py: authenticated decoder
# bindings must hash the same source bytes in source and portable deployments.
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules,copy_metadata

root = Path(SPECPATH).parent.parent
hidden = collect_submodules('wechat_capture_next', filter=lambda name:
    '.tests' not in name and '.desktop' not in name and
    not any(part in name for part in ('benchmark','profile_merge','live_probe','space_inventory','storage_ledger',
        'probe_video_native','comparison_','prepare_restore_cleanup','prepare_pair_restore_cleanup','pair_copy','repository_growth_accounting')))
a = Analysis([str(root/'wechat_capture_next'/'desktop'/'core_entry.py')],
    pathex=[str(root)],
    datas=[(str(root/'wechat_capture_next'/'product_web'),'wechat_capture_next/product_web')]+copy_metadata('pilk'),
    hiddenimports=hidden,
    excludes=['wechat_capture_next.tests','wechat_capture_v2.tests','pytest','tkinter'],
    module_collection_mode={'wechat_capture_next':'py','wechat_capture_v2':'py','wua':'py','tools':'py'})
pyz = PYZ(a.pure)
exe = EXE(pyz,a.scripts,[],exclude_binaries=True,name='CaptureNextCore',console=True)
coll = COLLECT(exe,a.binaries,a.datas,name='CaptureNextCore')

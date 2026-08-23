# Optional explicit PyInstaller spec. build_exe.bat does not require this file.
from PyInstaller.utils.hooks import collect_all

datas, binaries, hiddenimports = collect_all('rich')
binaries += [('bin/sing-box.exe', 'bin')]

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ApplicationSplitRouting',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
)

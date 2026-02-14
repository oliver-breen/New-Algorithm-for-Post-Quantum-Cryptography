# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path


project_dir = Path.cwd().resolve()
entry_script = project_dir / "gui" / "quantaweave_gui.py"
icon_file = project_dir / "assets" / "quantaweave.ico"
icon_arg = str(icon_file) if icon_file.exists() else None
block_cipher = None


a = Analysis(
    [str(entry_script)],
    pathex=[str(project_dir)],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='QuantaWeaveGUI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_arg,
)

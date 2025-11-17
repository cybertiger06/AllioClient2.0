# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('fondo.png', '.'),
        ('iniciofondo.png', '.'),
        ('fondoinstacia3.png', '.'),
        ('instacia1.png', '.'),
        ('instacia3.png', '.'),
        ('xbox.png', '.'),
        ('icono.png', '.'),
        ('icono.ico', '.'),
        ('1.png', '.'),
        ('Allio.png', '.'),
        ('README.txt', '.'),
        ('NAMETAGS.md', '.'),
        ('nametags.json', '.'),
        ('BackroomsMenu', 'BackroomsMenu'),
    ],
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
    name='Allio Client',
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
    icon=['icono.ico'],
)

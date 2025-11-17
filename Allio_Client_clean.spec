# -*- mode: python ; coding: utf-8 -*-

import os

block_cipher = None

# Archivos de datos que deben incluirse
datas = []

# Agregar solo los archivos que existen
import os
recursos = [
    'fondo.png',
    'iniciofondo.png',
    'fondoinstacia3.png',
    'instacia1.png',
    'instacia3.png',
    'xbox.png',
    'icono.png',
    'icono.ico',
    '1.png',
    'Allio.png',
    'README.txt',
    'NAMETAGS.md',
    'instaciaallio.png',
    'maximizar.png',
    'minimizar.png',
    'cerrar.png',
    'ajuste.png',
    'AllioAnimacion.gif',
    'logo_allio.png',
]

for recurso in recursos:
    if os.path.exists(recurso):
        datas.append((recurso, '.'))
    else:
        print(f"ADVERTENCIA: No se encontró {recurso}")

# Agregar carpetas si existen
if os.path.exists('BackroomsMenu'):
    datas.append(('BackroomsMenu', 'BackroomsMenu'))
if os.path.exists('HZ Menu'):
    datas.append(('HZ Menu', 'HZ Menu'))
if os.path.exists('Hardcore Instace'):
    datas.append(('Hardcore Instace', 'Hardcore Instace'))

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=['certifi', 'idna', 'charset_normalizer', 'requests', 'urllib3', 'minecraft_launcher_lib', 'pypresence'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
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
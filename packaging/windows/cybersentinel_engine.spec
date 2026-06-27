# -*- mode: python ; coding: utf-8 -*-
"""
Build: packaging/windows/build_engine.ps1
Output: packaging/windows/dist/CyberSentinelEngine/
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files

SPEC_DIR = Path(SPECPATH).resolve()
REPO_ROOT = SPEC_DIR.parent.parent
BACKEND = REPO_ROOT / "cybersentinel-backend"

block_cipher = None

# Only add submodules PyInstaller cannot trace. Do NOT use collect_submodules(sklearn)
# — that bundles every sklearn test and makes the build huge/slow.
hiddenimports = [
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan.on",
    "email_validator",
    "passlib.handlers.bcrypt",
    "asyncpg",
    "asyncpg.pgproto.pgproto",
    "asyncpg.protocol.protocol",
    "sklearn.utils._cython_blas",
    "sklearn.neighbors._partition_nodes",
    "sklearn.tree._utils",
    "sklearn.ensemble._forest",
    "imblearn",
    "greenlet",
    "sqlalchemy.dialects.sqlite",
    "sqlalchemy.dialects.postgresql.asyncpg",
    "reportlab.graphics.barcode.code128",
    "scapy.all",
    "scapy.layers.inet",
    "scapy.layers.l2",
    "scapy.sendrecv",
    "scapy.arch.windows",
]

datas = collect_data_files("sklearn", include_py_files=False)
datas += collect_data_files("scipy", include_py_files=False)

excludes = [
    "pytest",
    "pytest_asyncio",
    "IPython",
    "tkinter",
    "sklearn.tests",
    "passlib.tests",
    "asyncpg._testbase",
    "scipy.tests",
    "pandas.tests",
    "lightgbm",
    "matplotlib",
    "notebook",
]

a = Analysis(
    [str(BACKEND / "engine_main.py")],
    pathex=[str(BACKEND), str(REPO_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="cybersentinel_engine",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    uac_admin=True,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="CyberSentinelEngine",
)

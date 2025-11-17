import sys, os
import subprocess
import json
import time
import uuid
import base64
import hashlib
import importlib
import webbrowser
from datetime import datetime
from typing import Any, Optional 
from pathlib import Path
import requests

# Discord Rich Presence
try:
    from pypresence import Presence
except Exception:
    Presence = None

# Robustea la salida estándar para que NUNCA falle por Unicode en consolas cp1252 (evita cuelgues en otros PCs)
try:
    sys.stdout.reconfigure(errors='replace')
    sys.stderr.reconfigure(errors='replace')
except Exception:
    pass

# Parche global: sustituye print por una versión segura que nunca lanza UnicodeEncodeError
try:
    import builtins as _builtins  # type: ignore

    def _safe_print(*args, **kwargs):
        sep = kwargs.get('sep', ' ')
        end = kwargs.get('end', '\n')
        file = kwargs.get('file', sys.stdout)
        enc = getattr(file, 'encoding', None) or 'utf-8'
        try:
            text = sep.join(str(a) for a in args) + end
        except Exception:
            try:
                text = sep.join(repr(a) for a in args) + end
            except Exception:
                text = end
        # Reemplaza caracteres no representables en la consola destino
        try:
            file.write(text.encode(enc, errors='replace').decode(enc, errors='replace'))
        except Exception:
            try:
                # Último recurso: escribir directamente sin codificar
                file.write(text)
            except Exception:
                pass

    # Solo parchear si aún no está aplicado
    if getattr(_builtins, 'print', None) is not _safe_print:
        _builtins.print = _safe_print  # type: ignore
except Exception:
    # Si algo falla aquí, continuar con print estándar
    pass

try:
    from flask import Flask, request
except Exception:
    Flask = None  # type: ignore
    request = None  # type: ignore

try:
    import msal
except Exception:
    msal = None  # type: ignore

from PyQt6 .QtCore import Qt ,pyqtSignal ,QSize ,QRect ,QRectF ,QTimer ,QPropertyAnimation ,QPoint ,QEasingCurve ,QEvent 
from PyQt6 .QtGui import QPixmap ,QPainter ,QColor ,QFont ,QPainterPath ,QIcon ,QRegion ,QPen 
from PyQt6 .QtWidgets import (
QApplication ,QWidget ,QPushButton ,
QHBoxLayout ,QVBoxLayout ,QLineEdit ,QLabel ,QMessageBox ,QDialog ,QFileDialog ,QProgressBar ,
QSizePolicy ,QGraphicsDropShadowEffect ,QStyle ,QMenu ,QWidgetAction 
)
import threading
# Optional Windows API access for dark titlebar support
try:
    import ctypes
    from ctypes import wintypes
except Exception:
    ctypes = None
    wintypes = None
import threading ,urllib .request ,io ,urllib .parse 
import traceback 
import zipfile 
import shutil
import re

try:
    import minecraft_launcher_lib  # type: ignore
except Exception:
    minecraft_launcher_lib = None

APP_TITLE ="Allio Client 2.0"
BACKGROUND_FILE ="fondo.png"
CONFIG_FILE ="allio_config.json"
NOTIF_RIGHT_MARGIN = -16
MAX_GAMERTAG_LEN =32

_DEFAULT_MS_CLIENT_ID = "d6ef801b-876e-455c-977c-211fc6509c6b"
_DEFAULT_MS_REDIRECT_URI = "http://localhost:8114/redirect"
_DEFAULT_MS_FLASK_PORT = 8114


def _load_ms_oauth_overrides():
    """Carga overrides para MS OAuth desde variables de entorno o el archivo `allio_config.json`.

    Prioridad (mayor -> menor):
    1. Variables de entorno `ALLIO_MS_CLIENT_ID`, `ALLIO_MS_REDIRECT_URI`, `ALLIO_MS_FLASK_PORT`
    2. Archivo `allio_config.json` en la carpeta del proyecto (claves: `ms_client_id`, `ms_redirect_uri`, `ms_flask_port`)
    3. Valores por defecto codificados en el script
    """
    client_id = os.environ.get('ALLIO_MS_CLIENT_ID')
    redirect = os.environ.get('ALLIO_MS_REDIRECT_URI')
    flask_port = os.environ.get('ALLIO_MS_FLASK_PORT')

    # Intentar leer desde el config local si existe
    try:
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), CONFIG_FILE)
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    cfg = json.load(f) or {}
                # La app puede contener claves opcionales para sobrescribir
                if not client_id:
                    client_id = cfg.get('ms_client_id') or cfg.get('ms_clientid')
                if not redirect:
                    redirect = cfg.get('ms_redirect_uri') or cfg.get('ms_redirect')
                if not flask_port:
                    p = cfg.get('ms_flask_port')
                    if isinstance(p, int) or (isinstance(p, str) and p.isdigit()):
                        flask_port = int(p)
            except Exception:
                pass
    except Exception:
        pass

    client_id = client_id or _DEFAULT_MS_CLIENT_ID
    redirect = redirect or _DEFAULT_MS_REDIRECT_URI
    try:
        flask_port = int(flask_port) if flask_port is not None else _DEFAULT_MS_FLASK_PORT
    except Exception:
        flask_port = _DEFAULT_MS_FLASK_PORT

    return client_id, redirect, flask_port


def _default_username_from_seed(seed: str | None = None) -> str:
    """Genera un nombre por defecto razonable evitando 'Player'.

    Si se proporciona `seed`, intenta sanearla y usarla. Si está vacía,
    genera `Allio<hex>` con 6 caracteres para evitar duplicados.
    """
    try:
        s = (seed or '').strip()
        if s:
            s2 = re.sub(r'[^A-Za-z0-9_]', '', s)[:16]
            if s2:
                return s2
    except Exception:
        pass
    return f"Allio{uuid.uuid4().hex[:6]}"


def _ensure_username(value: str | None) -> str:
    """Normaliza un nombre de usuario, devuelve un valor no vacío diferente de 'Player'."""
    try:
        if isinstance(value, str):
            v = value.strip()
            if v:
                v = re.sub(r'[^A-Za-z0-9_]', '', v)[:16]
                if v:
                    return v
    except Exception:
        pass
    return _default_username_from_seed(None)


# Valores finales utilizados por el flujo de autenticación
MS_CLIENT_ID, MS_REDIRECT_URI, MS_FLASK_PORT = _load_ms_oauth_overrides()

# Forzar uso de 'localhost' en lugar de '127.0.0.1' para evitar mismatches
try:
    if isinstance(MS_REDIRECT_URI, str) and '127.0.0.1' in MS_REDIRECT_URI:
        MS_REDIRECT_URI = MS_REDIRECT_URI.replace('127.0.0.1', 'localhost')
        _append_run_log(f"Forced MS_REDIRECT_URI to: {MS_REDIRECT_URI}")
        print(f"[Allio OAuth] Forced MS_REDIRECT_URI to: {MS_REDIRECT_URI}")
except Exception:
    pass


def _get_normalized_redirect():
    """Devuelve una redirect URI normalizada usando 'localhost' y el puerto configurado.

    Esto fuerza que la URI enviada siempre coincida con la registrada en Azure
    cuando usemos el host local.
    """
    try:
        port = int(MS_FLASK_PORT) if MS_FLASK_PORT else 8114
    except Exception:
        port = 8114
    return f"http://localhost:{port}/redirect"

# Helper: escribir logs persistentes para debugging (append)
def _append_run_log(msg: str):
    try:
        path = os.path.join(os.path.dirname(__file__), 'run_log.txt')
        with open(path, 'a', encoding='utf-8') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except Exception:
        pass


def check_for_updates_async(manifest_url: str | None, timeout: int = 8):
    """Comprueba en segundo plano si hay una actualización disponible.

    El `manifest_url` debe apuntar a un JSON con al menos:
      { "version": "1.2.3", "url": "https://.../release.zip", "sha256": "..." }

    Si hay versión distinta, descarga el ZIP a `%APPDATA%/AllioClient/update/` y
    lanza `updater.py` para aplicar la actualización (se cierra el launcher).
    """
    if not manifest_url:
        return

    def _worker():
        try:
            print(f"[Allio Update] Comprobando manifest en: {manifest_url}")
            resp = requests.get(manifest_url, timeout=timeout)
            if resp.status_code != 200:
                print(f"[Allio Update] manifest no disponible: {resp.status_code}")
                return
            manifest = resp.json()
            new_version = str(manifest.get('version') or '')
            download_url = manifest.get('url')
            expected_hash = manifest.get('sha256')
            if not new_version or not download_url:
                print("[Allio Update] manifest inválido (faltan campos)")
                return

            # extraer versión actual de APP_TITLE (ej: 'Allio Client 2.0')
            cur_ver = ''
            try:
                cur_ver = APP_TITLE.split()[-1]
            except Exception:
                cur_ver = ''

            if new_version == cur_ver:
                print(f"[Allio Update] Ya estás en la versión {cur_ver}")
                return

            # Preparar directorios
            appdata = os.environ.get('APPDATA') or os.path.expanduser('~')
            upd_dir = os.path.join(appdata, 'AllioClient', 'update')
            os.makedirs(upd_dir, exist_ok=True)

            local_zip = os.path.join(upd_dir, 'release.zip')
            print(f"[Allio Update] Descargando {download_url} -> {local_zip}")
            dl = requests.get(download_url, timeout=30, stream=True)
            if dl.status_code != 200:
                print(f"[Allio Update] Error descargando release: {dl.status_code}")
                return
            with open(local_zip, 'wb') as f:
                for chunk in dl.iter_content(8192):
                    if chunk:
                        f.write(chunk)

            # Verificar hash si existe
            if expected_hash:
                h = hashlib.sha256()
                with open(local_zip, 'rb') as f:
                    for chunk in iter(lambda: f.read(8192), b''):
                        h.update(chunk)
                got = h.hexdigest()
                if got.lower() != expected_hash.lower():
                    print(f"[Allio Update] Hash mismatch: expected {expected_hash} got {got}")
                    return

            # Preferimos mostrar UI y permitir al usuario ver progreso; si hay un loop de Qt
            # disponible, programamos la UI para manejar la descarga y el lanzamiento del updater.
            try:
                app = QApplication.instance()
                if app is not None:
                    manifest_for_ui = { 'version': new_version, 'url': download_url, 'sha256': expected_hash }
                    QTimer.singleShot(0, lambda m=manifest_for_ui: _show_update_ui_and_apply(m))
                    return
            except Exception:
                pass

            # Fallback: lanzar updater directamente si no hay Qt loop disponible
            python_exe = sys.executable
            target_dir = os.path.dirname(os.path.abspath(__file__))
            updater_script = os.path.join(target_dir, 'updater.py')
            cmd = [python_exe, updater_script, local_zip, target_dir]
            print(f"[Allio Update] Lanzando updater (fallback): {cmd}")
            try:
                subprocess.Popen(cmd, close_fds=True)
            except Exception as e:
                print(f"[Allio Update] Error lanzando updater: {e}")
                return
            try:
                os._exit(0)
            except Exception:
                sys.exit(0)
        except Exception as e:
            print(f"[Allio Update] Error en worker: {e}")

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


class UpdateDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Application Update")
        self.setModal(True)
        self.setFixedSize(420, 100)
        v = QVBoxLayout(self)
        self.label = QLabel("Updating the application, please wait...")
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        v.addWidget(self.label)
        v.addWidget(self.progress)


def _show_update_ui_and_apply(manifest: dict):
    """Muestra UI modal, descarga con progreso y lanza updater."""
    try:
        app = QApplication.instance()
        parent = None
        if app is not None:
            parent = app.activeWindow()
        dlg = UpdateDialog(parent)

        def _download_and_apply():
            try:
                url = manifest.get('url')
                expected_hash = manifest.get('sha256')
                if not url:
                    QTimer.singleShot(0, lambda: QMessageBox.warning(parent, 'Update', 'Update URL missing'))
                    return
                # descargar con progreso
                resp = requests.get(url, stream=True, timeout=30)
                total = int(resp.headers.get('content-length') or 0)
                appdata = os.environ.get('APPDATA') or os.path.expanduser('~')
                upd_dir = os.path.join(appdata, 'AllioClient', 'update')
                os.makedirs(upd_dir, exist_ok=True)
                local_zip = os.path.join(upd_dir, 'release.zip')
                written = 0
                chunk_sz = 8192
                with open(local_zip, 'wb') as f:
                    for chunk in resp.iter_content(chunk_sz):
                        if not chunk:
                            continue
                        f.write(chunk)
                        written += len(chunk)
                        if total:
                            perc = int(written * 100 / total)
                        else:
                            # indeterminate fallback
                            perc = min(99, int(written / 1024))
                        QTimer.singleShot(0, lambda p=perc: dlg.progress.setValue(p))

                # verificar hash
                if expected_hash:
                    h = hashlib.sha256()
                    with open(local_zip, 'rb') as f:
                        for ch in iter(lambda: f.read(8192), b''):
                            h.update(ch)
                    if h.hexdigest().lower() != expected_hash.lower():
                        QTimer.singleShot(0, lambda: QMessageBox.critical(parent, 'Update', 'Downloaded file hash mismatch'))
                        return

                QTimer.singleShot(0, lambda: dlg.progress.setValue(100))
                # lanzar updater
                python_exe = sys.executable
                target_dir = os.path.dirname(os.path.abspath(__file__))
                updater_script = os.path.join(target_dir, 'updater.py')
                cmd = [python_exe, updater_script, local_zip, target_dir]
                try:
                    subprocess.Popen(cmd, close_fds=True)
                except Exception as e:
                    QTimer.singleShot(0, lambda: QMessageBox.critical(parent, 'Update', f'Unable to launch updater: {e}'))
                    return

                # exit app to allow updater to replace files
                time.sleep(0.5)
                try:
                    os._exit(0)
                except Exception:
                    sys.exit(0)
            except Exception as e:
                QTimer.singleShot(0, lambda: QMessageBox.critical(parent, 'Update', f'Update failed: {e}'))

        # start download thread and show dialog
        thr = threading.Thread(target=_download_and_apply, daemon=True)
        thr.start()
        dlg.exec()
    except Exception as e:
        try:
            print(f"[Allio Update] UI error: {e}")
        except Exception:
            pass

# NOTE: la sobreescritura de `MS_CLIENT_ID` desde `allio_config.json` ha sido
# deshabilitada intencionadamente para evitar que un valor de configuración
# local sobrescriba el valor codificado en el código. Si se desea reactivar
# esta funcionalidad, restaurar la lógica de lectura de `ms_client_id`.

# IMPORTANTE: Usar los mismos scopes que otras apps (compatibilidad)
# Si el usuario ya autorizó otra app con menos scopes, usar los mismos evita conflictos
MS_OAUTH_SCOPES = [
    "XboxLive.signin",
    "offline_access",
    # Scopes adicionales comentados para compatibilidad con otras aplicaciones
    # "openid",
    # "profile", 
    # "email",
]
MS_OAUTH_SCOPE = " ".join(MS_OAUTH_SCOPES)

MS_TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
XBOX_USER_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate"
XBOX_XSTS_URL = "https://xsts.auth.xboxlive.com/xsts/authorize"
MINECRAFT_LOGIN_URL = "https://api.minecraftservices.com/authentication/login_with_xbox"
MINECRAFT_PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile"
MINECRAFT_ENTITLEMENTS_URL = "https://api.minecraftservices.com/entitlements/mcstore"

# Use OS native title bar when True
USE_NATIVE_TITLEBAR = True

# --- Verificación automática de assets de sonido ---
def check_minecraft_assets(
    version_hint: str = "1.21",
    max_missing: int = 12,
    ensure_hashes: bool = True,
    return_details: bool = False,
) -> list[str] | tuple[list[str], dict[str, object]]:
    """Verifica que exista la estructura de assets de Minecraft y detecta archivos faltantes.

    Parámetros
    ---------
    version_hint: str
        Prefijo del índice a buscar dentro de ``assets/indexes``.
    max_missing: int
        Número máximo de objetos faltantes a devolver. Si es <= 0 no se limita.
    ensure_hashes: bool
        Cuando es True inspecciona el archivo de índice y valida la presencia/hash de cada objeto.
    return_details: bool
        Si es True devuelve ``(missing, details)`` donde ``details`` incluye rutas relevantes y el mapa de objetos.
    """
    try:
        appdata = os.getenv('APPDATA', '') or ''
        minecraft_dir = os.path.join(appdata, '.minecraft')
        assets_dir = os.path.join(minecraft_dir, 'assets')
        indexes_dir = os.path.join(assets_dir, 'indexes')
        objects_dir = os.path.join(assets_dir, 'objects')

        missing: list[str] = []
        details: dict[str, object] = {
            'minecraft_dir': minecraft_dir,
            'assets_dir': assets_dir,
            'objects_dir': objects_dir,
            'index_path': None,
            'objects_map': {},
        }

        if not os.path.isdir(indexes_dir):
            missing.append(os.path.join(assets_dir, 'indexes'))
            return (missing, details) if return_details else missing

        # Construir lista de candidatos para el archivo de índice esperado.
        candidates: list[str] = []
        if version_hint:
            normalized = version_hint.strip()
            if normalized:
                if not normalized.endswith('.json'):
                    candidates.append(f"{normalized}.json")
                else:
                    candidates.append(normalized)
                if '.' in normalized:
                    trunc = normalized.split('.')
                    if len(trunc) >= 2:
                        prefix = '.'.join(trunc[:2])
                        if not prefix.endswith('.json'):
                            prefix = f"{prefix}.json"
                        candidates.append(prefix)
        try:
            available_indexes = sorted([f for f in os.listdir(indexes_dir) if f.endswith('.json')], reverse=True)
        except Exception:
            available_indexes = []

        index_path = None
        for cand in candidates:
            path = os.path.join(indexes_dir, cand)
            if os.path.exists(path):
                index_path = path
                break
        if index_path is None and available_indexes:
            index_path = os.path.join(indexes_dir, available_indexes[0])

        if not index_path or not os.path.exists(index_path):
            missing.append(os.path.join(indexes_dir, candidates[0] if candidates else '1.21.json'))
            return (missing, details) if return_details else missing

        details['index_path'] = index_path

        if not os.path.isdir(objects_dir):
            missing.append(objects_dir)
            return (missing, details) if return_details else missing

        if ensure_hashes:
            try:
                with open(index_path, 'r', encoding='utf-8') as idx_file:
                    index_data = json.load(idx_file) or {}
                objects = index_data.get('objects', {}) if isinstance(index_data, dict) else {}
                if isinstance(objects, dict):
                    details['objects_map'] = objects
                else:
                    objects = {}
                unlimited = max_missing is None or max_missing <= 0
                missing_objects: list[str] = []
                for asset_name, asset_info in objects.items():
                    if not isinstance(asset_info, dict):
                        continue
                    asset_hash = asset_info.get('hash')
                    if not asset_hash or len(asset_hash) < 2:
                        continue
                    subdir = asset_hash[:2]
                    asset_path = os.path.join(objects_dir, subdir, asset_hash)
                    if not os.path.exists(asset_path):
                        missing_objects.append(asset_path)
                    else:
                        try:
                            expected_size = int(asset_info.get('size', 0))
                        except Exception:
                            expected_size = 0
                        if expected_size and expected_size > 0:
                            try:
                                if os.path.getsize(asset_path) != expected_size:
                                    missing_objects.append(asset_path + ' (size mismatch)')
                            except Exception:
                                missing_objects.append(asset_path)
                    if not unlimited and max_missing and len(missing_objects) >= max_missing:
                        break
                missing.extend(missing_objects)
            except Exception as asset_exc:
                print(f"[Allio] Error validando assets con {index_path}: {asset_exc}")

        return (missing, details) if return_details else missing
    except Exception as exc:
        print(f"[Allio] check_minecraft_assets error: {exc}")
        if return_details:
            return [], {'minecraft_dir': '', 'assets_dir': '', 'objects_dir': '', 'index_path': None, 'objects_map': {}}
        return []
def center_widget(win):
    """Mueve `win` al centro de la pantalla primaria.

    Llamar preferentemente después de `show()` usando `QTimer.singleShot`.
    """
    try:
        app = QApplication.instance()
        if app is None:
            return
        try:
            screen = app.primaryScreen()
            if screen is not None:
                screen_geo = screen.availableGeometry()
            else:
                screen_geo = app.primaryScreen().availableGeometry()
        except Exception:
            # fallback: usar la geometría de la pantalla principal por defecto
            screen_geo = app.primaryScreen().availableGeometry()

        # Frame geometry incluye el marco de ventana
        try:
            fg = win.frameGeometry()
        except Exception:
            fg = win.geometry()

        try:
            center_point = screen_geo.center()
            fg.moveCenter(center_point)
            win.move(fg.topLeft())
        except Exception:
            # último recurso: centrar por cálculo simple
            try:
                w = win.width()
                h = win.height()
                x = max(0, screen_geo.left() + (screen_geo.width() - w) // 2)
                y = max(0, screen_geo.top() + (screen_geo.height() - h) // 2)
                win.move(x, y)
            except Exception:
                pass
    except Exception:
        # Si ocurre cualquier error al intentar centrar, no interrumpir la aplicación
        try:
            return
        except Exception:
            pass


def _download_asset_hash(objects_dir: str, asset_hash: str, expected_size: int | None = None) -> bool:
    """Descarga un asset individual desde los servidores de Mojang usando el hash SHA1."""
    try:
        url = f"https://resources.download.minecraft.net/{asset_hash[:2]}/{asset_hash}"
        for verify_flag in (True, False):
            try:
                resp = requests.get(url, timeout=25, verify=verify_flag)
            except Exception:
                continue
            if resp.status_code == 200:
                content = resp.content
                if expected_size and expected_size > 0 and len(content) != expected_size:
                    continue
                target_dir = os.path.join(objects_dir, asset_hash[:2])
                os.makedirs(target_dir, exist_ok=True)
                with open(os.path.join(target_dir, asset_hash), 'wb') as fout:
                    fout.write(content)
                return True
        return False
    except Exception as exc:
        print(f"[Allio] Error directo descargando asset {asset_hash}: {exc}")
        return False


def download_missing_minecraft_assets(
    version: str,
    minecraft_dir: str,
    missing_paths: list[str] | None = None,
    objects_map: dict | None = None,
) -> bool:
    """Descarga/instala los assets necesarios para la versión indicada usando minecraft-launcher-lib.

    Devuelve True si la operación parece haber terminado correctamente.
    """
    if not version:
        return False
    if minecraft_launcher_lib is None:
        print("[Allio] minecraft_launcher_lib no disponible: no se pueden descargar assets automáticamente")
        return False
    try:
        from minecraft_launcher_lib import install  # type: ignore
    except Exception as import_err:
        print(f"[Allio] No se pudo importar install desde minecraft_launcher_lib: {import_err}")
        return False

    try:
        version_id = str(version)
        print(f"[Allio] Descargando/verificando assets para {version_id}...")
        install_ok = True
        try:
            install.install_minecraft_version(version_id, minecraft_dir)
        except Exception as inst_exc:
            install_ok = False
            print(f"[Allio] Aviso: install_minecraft_version falló ({inst_exc})")

        version_json_path = os.path.join(minecraft_dir, 'versions', version_id, f"{version_id}.json")
        version_data = {}
        if os.path.exists(version_json_path):
            try:
                with open(version_json_path, 'r', encoding='utf-8') as vfile:
                    version_data = json.load(vfile) or {}
            except Exception as read_exc:
                print(f"[Allio] No se pudo leer {version_json_path}: {read_exc}")

        try:
            install.install_assets(version_data, minecraft_dir, {})
        except Exception as assets_exc:
            install_ok = False
            print(f"[Allio] Aviso: install_assets lanzó una excepción: {assets_exc}")
            # Aun así, continuar con la descarga manual.

        repaired = install_ok
        manual_success = False

        if missing_paths and objects_map:
            objects_dir = os.path.join(minecraft_dir, 'assets', 'objects')
            hash_to_meta = {}
            for name, meta in objects_map.items():
                if isinstance(meta, dict) and 'hash' in meta:
                    hash_to_meta[str(meta['hash'])] = meta
            for path in missing_paths:
                if not isinstance(path, str):
                    continue
                asset_hash = os.path.basename(path).split(' ')[0]
                meta = hash_to_meta.get(asset_hash)
                size = None
                if isinstance(meta, dict):
                    try:
                        size_val = meta.get('size')
                        size = int(size_val) if size_val is not None else None
                    except Exception:
                        size = None
                ok = _download_asset_hash(objects_dir, asset_hash, size)
                if ok:
                    manual_success = True
                else:
                    repaired = False
                    print(f"[Allio] No se pudo descargar {asset_hash} con fallback directo")

        if manual_success and not repaired:
            repaired = True

        return repaired
    except Exception as exc:
        print(f"[Allio] Error descargando assets para {version}: {exc}")
        return False


def _version_sort_key(version: str) -> tuple[tuple[int, ...], str]:
    """Normaliza un string de versión extrayendo componentes numéricos para comparaciones simples."""
    nums = []
    for chunk in re.findall(r"\d+", version):
        try:
            nums.append(int(chunk))
        except Exception:
            pass
    return tuple(nums), version


def is_zip_valid(path: str) -> bool:
    """Comprueba la integridad de un archivo ZIP/JAR. Devuelve True si es válido."""
    try:
        if not os.path.exists(path):
            return False
        # zipfile.testzip devuelve None si todo está bien, o el nombre del primer archivo corrupto
        with zipfile.ZipFile(path, 'r') as zf:
            bad = zf.testzip()
            if bad is not None:
                print(f"[Allio] ZIP corrupto detectado en {path}, entrada: {bad}")
                return False
        return True
    except zipfile.BadZipFile:
        print(f"[Allio] BadZipFile: {path}")
        return False
    except Exception as e:
        print(f"[Allio] Error comprobando ZIP {path}: {e}")
        return False


def validate_and_cleanup_corrupt_jars(minecraft_dir: str) -> list:
    """Recorre la carpeta 'libraries' y 'versions' buscando JARs corruptos.
    Si detecta JARs corruptos los mueve a una subcarpeta 'corrupt_libraries' y devuelve la lista.
    Esto evita que Fabric/launcher falle leyendo jars corruptos (zip END header not found).
    """
    moved = []
    try:
        libraries_dir = os.path.join(minecraft_dir, 'libraries')
        versions_dir = os.path.join(minecraft_dir, 'versions')
        corrupt_dir = os.path.join(minecraft_dir, 'corrupt_libraries')
        os.makedirs(corrupt_dir, exist_ok=True)

        candidates = []
        if os.path.exists(libraries_dir):
            for root, dirs, files in os.walk(libraries_dir):
                for f in files:
                    if f.lower().endswith('.jar'):
                        candidates.append(os.path.join(root, f))

        if os.path.exists(versions_dir):
            for root, dirs, files in os.walk(versions_dir):
                for f in files:
                    if f.lower().endswith('.jar'):
                        candidates.append(os.path.join(root, f))

        for jar in candidates:
            try:
                if not is_zip_valid(jar):
                    # mover a carpeta de cuarentena (preservar estructura relativa)
                    rel = os.path.relpath(jar, minecraft_dir)
                    dest = os.path.join(corrupt_dir, rel.replace(os.sep, '__'))
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    try:
                        shutil.move(jar, dest)
                        moved.append((jar, dest))
                        print(f"[Allio] Movido jar corrupto: {jar} -> {dest}")
                    except Exception as mv_e:
                        print(f"[Allio] No se pudo mover {jar}: {mv_e}")
            except Exception as e:
                print(f"[Allio] Error validando jar {jar}: {e}")
    except Exception as e:
        print(f"[Allio] Error en validate_and_cleanup_corrupt_jars: {e}")
    return moved


def quarantine_duplicate_library_versions(minecraft_dir: str) -> list[tuple[str, str]]:
    """Detecta versiones duplicadas de bibliotecas y mueve las más antiguas."""
    moved: list[tuple[str, str]] = []
    try:
        libraries_dir = os.path.join(minecraft_dir, 'libraries')
        if not os.path.isdir(libraries_dir):
            return moved

        duplicates_root = os.path.join(minecraft_dir, 'duplicate_libraries')
        os.makedirs(duplicates_root, exist_ok=True)

        artifact_versions: dict[tuple[str, ...], list[tuple[tuple[int, ...], str]]] = {}
        for root, _, files in os.walk(libraries_dir):
            for name in files:
                if not name.lower().endswith('.jar'):
                    continue
                jar_path = os.path.join(root, name)
                rel_path = os.path.relpath(jar_path, libraries_dir)
                parts = rel_path.split(os.sep)
                if len(parts) < 3:
                    continue
                artifact_key = tuple(parts[:-2]) + (parts[-1],)
                version_token = parts[-2]
                version_tuple: tuple[int, ...] = tuple()
                try:
                    version_tuple = tuple(int(x) for x in re.findall(r"\d+", version_token))
                except Exception:
                    pass
                artifact_versions.setdefault(artifact_key, []).append((version_tuple, jar_path))

        for versions in artifact_versions.values():
            if len(versions) <= 1:
                continue
            versions.sort(key=lambda item: item[0])
            to_keep = versions[-1][1]
            for _, path in versions[:-1]:
                rel = os.path.relpath(path, libraries_dir)
                dest = os.path.join(duplicates_root, rel)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                try:
                    shutil.move(path, dest)
                    moved.append((path, dest))
                    print(f"[Allio] Librería duplicada movida: {path} -> {dest}")
                except Exception as move_err:
                    print(f"[Allio] No se pudo mover {path}: {move_err}")
        return moved
    except Exception as exc:
        print(f"[Allio] Error detectando duplicados: {exc}")
        return moved


def ensure_lwjgl_natives(version_dir: str, libraries_dir: str) -> tuple[bool, list[str]]:
    """Extrae los natives de LWJGL para Windows al directorio indicado."""
    extracted: list[str] = []
    try:
        natives_dir = os.path.join(version_dir, 'natives')
        os.makedirs(natives_dir, exist_ok=True)

        candidate_jars: list[str] = []
        for root, _, files in os.walk(libraries_dir):
            for name in files:
                lower = name.lower()
                if not lower.endswith('.jar'):
                    continue
                if 'natives' in lower and 'windows' in lower:
                    candidate_jars.append(os.path.join(root, name))

        if not candidate_jars:
            print(f"[Allio] No se encontraron JARs de natives de LWJGL en {libraries_dir}")
            return False, extracted

        for entry in os.listdir(natives_dir):
            path = os.path.join(natives_dir, entry)
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    os.remove(path)
            except Exception:
                pass

        for jar_path in candidate_jars:
            try:
                with zipfile.ZipFile(jar_path, 'r') as zf:
                    for member in zf.namelist():
                        if member.endswith('/'):
                            continue
                        filename = os.path.basename(member)
                        if not filename:
                            continue
                        target_path = os.path.join(natives_dir, filename)
                        with zf.open(member) as src, open(target_path, 'wb') as dst:
                            shutil.copyfileobj(src, dst)
                        extracted.append(target_path)
            except Exception as extract_exc:
                print(f"[Allio] Error extrayendo natives desde {jar_path}: {extract_exc}")

        if not extracted:
            print(f"[Allio] No se extrajo ningún native a {natives_dir}")
            return False, extracted

        return True, extracted
    except Exception as exc:
        print(f"[Allio] Error preparando natives: {exc}")
        return False, extracted


def load_official_launcher_session(minecraft_dir: str) -> dict[str, object]:
    """Intenta cargar la sesión activa desde launcher_accounts.json del launcher oficial."""
    try:
        accounts_files = [
            os.path.join(minecraft_dir, 'launcher_accounts.json'),
            os.path.join(minecraft_dir, 'launcher_accounts_microsoft_store.json'),
        ]
        best_match: tuple[tuple[int, float], dict[str, object]] | None = None
        now = time.time()

        for path in accounts_files:
            print(f"[Allio Debug] Verificando archivo: {path}")
            if not os.path.isfile(path):
                print(f"[Allio Debug] Archivo no existe: {path}")
                continue
            print(f"[Allio Debug] Archivo existe, intentando leer...")
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    data = json.load(fh) or {}
                print(f"[Allio Debug] JSON cargado, claves: {list(data.keys())}")
            except Exception as read_exc:
                print(f"[Allio] No se pudo leer {path}: {read_exc}")
                continue

            accounts = data.get('accounts')
            if not isinstance(accounts, dict):
                print(f"[Allio Debug] No hay diccionario de cuentas en {path}")
                continue
            print(f"[Allio Debug] Encontradas {len(accounts)} cuentas")
            active_id = data.get('activeAccountLocalId') or data.get('activeUser')
            client_token_default = data.get('clientToken') or data.get('client_token')

            for acc_id, acc_data in accounts.items():
                if not isinstance(acc_data, dict):
                    continue
                    
                print(f"[Allio Debug] Procesando cuenta: {acc_id}")
                print(f"[Allio Debug] Claves de cuenta: {list(acc_data.keys())}")
                
                token = acc_data.get('accessToken') or acc_data.get('access_token')
                if not token:
                    print(f"[Allio Debug] ⚠️ Cuenta {acc_id} no tiene accessToken")
                    continue
                    
                print(f"[Allio Debug] ✅ Token encontrado para {acc_id} ({len(token)} chars)")

                profile = {}
                if isinstance(acc_data.get('minecraftProfile'), dict):
                    profile = acc_data['minecraftProfile']
                elif isinstance(acc_data.get('profile'), dict):
                    profile = acc_data['profile']

                uuid_raw = profile.get('id') or acc_data.get('minecraftUuid') or acc_data.get('uuid')
                if not isinstance(uuid_raw, str):
                    continue
                uuid_hex = uuid_raw.replace('-', '')
                if len(uuid_hex) != 32:
                    continue
                uuid_formatted = f"{uuid_hex[0:8]}-{uuid_hex[8:12]}-{uuid_hex[12:16]}-{uuid_hex[16:20]}-{uuid_hex[20:32]}"

                username = profile.get('name') or acc_data.get('minecraftName') or acc_data.get('name') or uuid_formatted
                expires_raw = acc_data.get('expiresAt') or acc_data.get('expires_at')
                expires_ts: float | None = None
                if isinstance(expires_raw, (int, float)):
                    expires_ts = float(expires_raw)
                elif isinstance(expires_raw, str):
                    try:
                        expires_ts = datetime.fromisoformat(expires_raw.replace('Z', '+00:00')).timestamp()
                    except Exception:
                        expires_ts = None

                session_payload: dict[str, object] = {
                    'minecraft_token': token,
                    'minecraft_username': username,
                    'minecraft_uuid': uuid_formatted,
                    'minecraft_uuid_nodash': uuid_hex,
                    'client_token': acc_data.get('clientToken') or client_token_default or acc_id,
                    'xuid': acc_data.get('xuid') or '',
                    'ms_refresh_token': acc_data.get('refreshToken') or acc_data.get('refresh_token') or '',
                    'ms_access_token': acc_data.get('msAccessToken') or acc_data.get('ms_access_token') or '',
                    'ms_account_email': acc_data.get('emailAddress') or acc_data.get('email') or '',
                    'minecraft_token_expires_at': expires_ts if expires_ts is not None else 0.0,
                    'auth_source': path,
                }

                priority = (
                    1 if acc_id == active_id else 0,
                    1 if not expires_ts or expires_ts > now else 0,
                    expires_ts or 0.0,
                )

                if best_match is None or priority > best_match[0]:
                    best_match = (priority, session_payload)

        if best_match is not None:
            payload = best_match[1]
            print(f"[Allio] Sesión importada desde launcher oficial: {payload.get('minecraft_username')} ({payload.get('auth_source')})")
            return payload
    except Exception as exc:
        print(f"[Allio] Error leyendo sesión del launcher oficial: {exc}")
    return {}


def find_local_minecraft_candidates(search_roots=None, max_results=5):
    """Buscar instalaciones locales de Minecraft que contengan assets/indexes/1.21.json.
    Devuelve la lista de rutas a la carpeta raíz de Minecraft (la que contiene 'assets').
    """
    if search_roots is None:
        search_roots = [os.getcwd(), os.path.expanduser('~')]
    found = []
    for root in search_roots:
        for dirpath, dirnames, filenames in os.walk(root):
            # limitar la búsqueda en profundidad por performance
            rel = os.path.relpath(dirpath, root)
            if rel.count(os.sep) > 4:
                # skip deep dirs
                dirnames[:] = []
                continue
            # mirar si aquí hay assets/indexes/1.21.json
            candidate = os.path.join(dirpath, 'assets', 'indexes', '1.21.json')
            if os.path.exists(candidate):
                # dirpath is likely the .minecraft root
                if dirpath not in found:
                    found.append(dirpath)
                    if len(found) >= max_results:
                        return found
    return found


def reparar_sonidos_minecraft(origen=None):
    """
    Detecta archivos de sonido faltantes y, si se proporciona una ruta de origen válida, los copia automáticamente.
    Retorna True si la copia fue exitosa.
    """
    try:
        appdata = os.getenv('APPDATA', '')
        sounds_dir = os.path.join(appdata, '.minecraft', 'assets', 'objects')
        if not os.path.exists(sounds_dir):
            os.makedirs(sounds_dir, exist_ok=True)
        # Si origen es una carpeta raíz que contiene 'assets/objects'
        if origen and os.path.exists(origen):
            origen_sounds = os.path.join(origen, 'assets', 'objects')
            if os.path.exists(origen_sounds):
                for root, dirs, files in os.walk(origen_sounds):
                    rel = os.path.relpath(root, origen_sounds)
                    dest_dir = os.path.join(sounds_dir, rel) if rel != '.' else sounds_dir
                    os.makedirs(dest_dir, exist_ok=True)
                    for f in files:
                        try:
                            src_file = os.path.join(root, f)
                            dest_file = os.path.join(dest_dir, f)
                            if not os.path.exists(dest_file):
                                shutil.copy2(src_file, dest_file)
                        except Exception:
                            pass
                return True
        # Fallback: nada copiado
        return False
    except Exception as e:
        print(f"[Allio] Error reparar_sonidos_minecraft: {e}")
        return False

def _computed_titlebar_height(parent: Optional[QWidget]) -> int:
    try:
        if not globals().get('USE_NATIVE_TITLEBAR', False):
            if parent is not None and hasattr(parent, 'titleBar') and getattr(parent, 'titleBar') is not None:
                try:
                    return int(parent.titleBar.height())
                except Exception:
                    pass
            return 44
        # Native titlebar: use style metric
        try:
            style = QApplication.style() if QApplication is not None else None
            if style is not None:
                val = style.pixelMetric(QStyle.PM_TitleBarHeight)
                if isinstance(val, int) and val > 8:
                    return val
        except Exception:
            pass
        return 44
    except Exception:
        return 44

def resource_path (relative_path ):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try :
        base_path =sys ._MEIPASS 
    except Exception :
        base_path =os .path .abspath (".")
    return os .path .join (base_path ,relative_path )

def is_running_as_executable():
    """Detecta si la aplicación se está ejecutando como un ejecutable compilado"""
    return hasattr(sys, '_MEIPASS') or getattr(sys, 'frozen', False)


def get_minecraft_java_resource_packs_path()->str:
    """Resolver la ruta de resourcepacks de Minecraft Java Edition para el usuario actual en Windows.
    Devuelve la ruta si existe o una ruta por defecto donde intentar copiar.
    """
    try:
        # Ruta estándar de Minecraft Java en Windows
        minecraft_java_path = os.path.join(os.getenv('APPDATA', ''), '.minecraft', 'resourcepacks')
        if os.path.exists(minecraft_java_path):
            return minecraft_java_path
            
        # Crear la carpeta si no existe
        try:
            os.makedirs(minecraft_java_path, exist_ok=True)
            return minecraft_java_path
        except Exception:
            pass
            
        # Fallback a una ruta alternativa
        fallback = os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming', '.minecraft', 'resourcepacks')
        return fallback
    except Exception:
        return os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming', '.minecraft', 'resourcepacks')


def get_bedrock_resource_packs_path ()->str :
    """Resolver la ruta de resource_packs de Minecraft Bedrock para el usuario actual en Windows.
    Devuelve la ruta si existe o una ruta por defecto donde intentar copiar.
    """
    try :
        local =os .getenv ('LOCALAPPDATA')
        if local :
            candidate =os .path .join (local ,'Packages','Microsoft.MinecraftUWP_8wekyb3d8bbwe','LocalState','games','com.mojang','resource_packs')
            if os .path .exists (candidate ):
                return candidate 
        appd =os .getenv ('APPDATA')or os .getenv ('USERPROFILE')
        if appd :
            candidate2 =os .path .join (appd ,'com.mojang','resource_packs')
            if os .path .exists (candidate2 ):
                return candidate2 

        fallback =os .path .join (os .path .expanduser ('~'),'AppData','Local','Packages','Microsoft.MinecraftUWP_8wekyb3d8bbwe','LocalState','games','com.mojang','resource_packs')
        return fallback 
    except Exception :
        return os .path .join (os .path .expanduser ('~'),'AppData','Local','Packages','Microsoft.MinecraftUWP_8wekyb3d8bbwe','LocalState','games','com.mojang','resource_packs')


def create_mcpack_from_folder (folder :str ,out_path :str )->bool :
    """Crea un .mcpack (zip) desde una carpeta de resource pack."""
    try :
        base =os .path .abspath (folder )
        if not os .path .isdir (base ):
            return False 
        with zipfile .ZipFile (out_path ,'w',zipfile .ZIP_DEFLATED )as zf :
            for root ,dirs ,files in os .walk (base ):
                for f in files :
                    full =os .path .join (root ,f )
                    arc =os .path .relpath (full ,base )
                    zf .write (full ,arc )
        return True 
    except Exception as e :
        print (f"[Allio] Error creando mcpack: {e}")
        return False 


def install_resource_pack_from_folder (folder :str )->bool :
    """Intentar instalar el resource pack: copiar carpeta a resource_packs; si falla, crear .mcpack y abrirlo para importar."""
    try :
        folder =os .path .abspath (folder )
        if not os .path .exists (folder ):
            print (f"[Allio] Resource pack folder no existe: {folder}")
            return False 

        rp_path =get_minecraft_java_resource_packs_path ()
        try :
            os .makedirs (rp_path ,exist_ok =True )
        except Exception :
            pass 

        dest =os .path .join (rp_path ,os .path .basename (folder ))
        try :
            if os .path .exists (dest ):
                import shutil 
                try :
                    shutil .rmtree (dest )
                except Exception :
                    pass 
            import shutil 
            shutil .copytree (folder ,dest )
            print (f"[Allio] Resource pack copiado a: {dest}")
            return True 
        except Exception as e :
            print (f"[Allio] No se pudo copiar resource pack directamente: {e}")
        try :
            tmp_mcpack =os .path .join (os .path .expanduser ('~'),os .path .basename (folder )+'.mcpack')
            ok =create_mcpack_from_folder (folder ,tmp_mcpack )
            if ok :
                try :
                    if sys .platform .startswith ('win'):
                        os .startfile (tmp_mcpack )
                    else :
                        subprocess .Popen (['xdg-open',tmp_mcpack ])
                    print (f"[Allio] Abriendo {tmp_mcpack} para importarlo en Minecraft.")
                    return True 
                except Exception as e :
                    print (f"[Allio] Error abriendo mcpack: {e}")
        except Exception as e :
            print (f"[Allio] Error creando/abriendo mcpack: {e}")
        return False 
    except Exception as e :
        print (f"[Allio] install_resource_pack_from_folder error: {e}")
        return False 

class RoundIconButton (QPushButton ):
    """Botón completamente circular con icono centrado y máscara suave."""
    def __init__ (self ,image_path :str |None =None ,size :int =44 ,tooltip :str ="",padding :int =2 ):
        super ().__init__ ()
        self ._size =max (12 ,int (size ))
        self ._pad =max (0 ,int (padding ))
        self .setFixedSize (self ._size ,self ._size )
        self .setFlat (True )
        self .setCursor (Qt .CursorShape .PointingHandCursor )
        self .setFocusPolicy (Qt .FocusPolicy .NoFocus )
        try :
            self .setAttribute (Qt .WidgetAttribute .WA_TranslucentBackground ,True )
        except Exception :
            pass 


        try :
            self .setStyleSheet (f"""
                QPushButton {{
                    background: transparent;
                    border: none;
                    border-radius: {self._size//2}px;
                    padding: 0;
                    outline: none;
                }}
                QPushButton:hover {{ background: rgba(255,255,255,0.01); }}
                QPushButton:pressed {{ background: rgba(255,255,255,0.02); }}
            """)
        except Exception :
            pass 
        if tooltip :
            try :
                self .setToolTip (tooltip )
            except Exception :
                pass 

        if image_path and os .path .exists (image_path ):
            try :
                pm =QPixmap (image_path )
                if not pm .isNull ():
                    inner =max (4 ,self ._size -self ._pad *2 )
                    icon_pm =pm .scaled (inner ,inner ,Qt .AspectRatioMode .KeepAspectRatioByExpanding ,Qt .TransformationMode .SmoothTransformation )
                    circ =QPixmap (self ._size ,self ._size )
                    circ .fill (Qt .GlobalColor .transparent )
                    painter =QPainter (circ )
                    painter .setRenderHint (QPainter .RenderHint .Antialiasing )
                    path =QPainterPath ()
                    path .addEllipse (self ._pad ,self ._pad ,inner ,inner )
                    painter .setClipPath (path )

                    dx =self ._pad +(inner -icon_pm .width ())//2 
                    dy =self ._pad +(inner -icon_pm .height ())//2 
                    painter .drawPixmap (dx ,dy ,icon_pm )
                    painter .end ()
                    try :
                        self .setIcon (QIcon (circ ))

                        self .setIconSize (QSize (self ._size ,self ._size ))
                    except Exception :
                        pass 
            except Exception :
                pass 


        try :
            p =QPainterPath ()
            p .addEllipse (0.0 ,0.0 ,float (self ._size ),float (self ._size ))
            region =QRegion (p .toFillPolygon ().toPolygon ())
            self .setMask (region )
        except Exception :
            pass 


class NotificationWidget (QWidget ):
    """Pequeña notificación en esquina superior derecha con icono, texto y barra de progreso.
    Uso: crear con parent=ventana principal y llamar a show_for(text, duration_ms)
    """
    def __init__ (self ,parent =None ):
        super ().__init__ (parent )

        try :
            self .setWindowFlags (Qt .WindowType .FramelessWindowHint )
        except Exception :
            pass 

        try :
            self .setAttribute (Qt .WidgetAttribute .WA_TranslucentBackground )
        except Exception :
            pass 
        self .setFixedSize (240 ,64 )


        lay =QVBoxLayout (self )
        lay .setContentsMargins (8 ,8 ,8 ,8 )
        lay .setSpacing (4 )

        top =QWidget ()
        th =QHBoxLayout (top )
        th .setContentsMargins (6 ,0 ,6 ,0 )
        th .setSpacing (8 )


        self .icon_label =QLabel ()
        self .icon_label .setFixedSize (36 ,36 )
        self .icon_label .setStyleSheet ("border-radius:18px; background: #2ecc71; color: white; font-weight:700; text-align:center; border:1px solid rgba(0,0,0,0.06);")
        self .icon_label .setAlignment (Qt .AlignmentFlag .AlignCenter )

        self .icon_label .setText ("✓")
        th .addWidget (self .icon_label ,0 )

        self .text_label =QLabel ("")

        self .text_label .setStyleSheet ("color: #222222; font: 600 14px 'Avenir, Segoe UI';")
        self .text_label .setAlignment (Qt .AlignmentFlag .AlignVCenter |Qt .AlignmentFlag .AlignLeft )
        th .addWidget (self .text_label ,1 )

        lay .addWidget (top )


        self .progress =QProgressBar ()
        self .progress .setFixedHeight (6 )
        self .progress .setRange (0 ,1000 )
        self .progress .setValue (1000 )
        self .progress .setTextVisible (False )

        self .progress .setStyleSheet ("QProgressBar{background:rgba(0,0,0,0.06); border-radius:3px;} QProgressBar::chunk{background:#2ecc71; border-radius:3px;}")
        lay .addWidget (self .progress )

        self ._timer =QTimer (self )
        self ._timer .setInterval (40 )
        self ._remaining =0 
        self ._duration =0 
        self ._timer .timeout .connect (self ._tick )

        try :
            self ._anim_in =QPropertyAnimation (self ,b"pos")
            self ._anim_in .setEasingCurve (QEasingCurve .Type .OutCubic )
            self ._anim_in .setDuration (280 )
            self ._anim_out =QPropertyAnimation (self ,b"pos")
            self ._anim_out .setEasingCurve (QEasingCurve .Type .InCubic )
            self ._anim_out .setDuration (220 )
        except Exception :
            self ._anim_in =None 
            self ._anim_out =None 

    def paintEvent (self ,e ):

        p =QPainter (self )
        p .setRenderHint (QPainter .RenderHint .Antialiasing )
        rect =self .rect ()

        color =QColor (255 ,255 ,255 ,235 )
        p .setBrush (color )
        p .setPen (Qt .PenStyle .NoPen )
        p .drawRoundedRect (rect ,10 ,10 )
        super ().paintEvent (e )

    def show_for (self ,text :str ,duration_ms :int =2000 ):

        try :
            self .text_label .setText (text )
        except Exception :
            pass 
        self ._duration =max (200 ,int (duration_ms ))
        self ._remaining =self ._duration 
        try :
            self .progress .setRange (0 ,self ._duration )
            self .progress .setValue (self ._duration )
        except Exception :
            pass 
        self .adjustSize ()

        self .show_with_animation ()
        self ._timer .start ()

    def show_with_animation (self ):
        """Muestra el widget con una animación deslizante desde la derecha."""

        try :
            parent =self .parent ()if self .parent ()is not None else self .window ()
            target_x =self .x ()
            target_y =self .y ()

            start_x =parent .width ()+16 if parent is not None else target_x +40 
            start_pos =QPoint (start_x ,target_y )
            end_pos =QPoint (target_x ,target_y )

            try :
                if self ._anim_out is not None :
                    self ._anim_out .stop ()
            except Exception :
                pass 

            try :
                self .move (start_pos )
                self .show ()
                self .raise_ ()
            except Exception :
                pass 
            if self ._anim_in is not None :
                try :

                    try :
                        print (f"[Notification] start anim_in from {start_pos.x()},{start_pos.y()} to {end_pos.x()},{end_pos.y()}")
                    except Exception :
                        print ("[Notification] start anim_in")
                    self ._anim_in .stop ()
                    self ._anim_in .setStartValue (start_pos )
                    self ._anim_in .setEndValue (end_pos )
                    try :

                        try :
                            self ._anim_in .finished .disconnect ()
                        except Exception :
                            pass 
                        self ._anim_in .finished .connect (lambda :print ("[Notification] anim_in finished"))
                    except Exception :
                        pass 
                    self ._anim_in .start ()
                except Exception :
                    pass 
        except Exception :
            try :
                self .show ()
                self .raise_ ()
            except Exception :
                pass 

    def hide_with_animation (self ):
        """Oculta el widget con una animación deslizante hacia la derecha y oculta al terminar."""
        try:
            parent = self.parent() if self.parent() is not None else self.window()
            cur_pos = self.pos()
            off_x = parent.width() + 24 if parent is not None else cur_pos.x() + 40
            end_pos = QPoint(off_x, cur_pos.y())
            try:
                if self._anim_in is not None:
                    self._anim_in.stop()
            except Exception:
                pass
            if self._anim_out is not None:
                try:
                    try:
                        print(f"[Notification] start anim_out from {cur_pos.x()},{cur_pos.y()} to {end_pos.x()},{end_pos.y()}")
                    except Exception:
                        print("[Notification] start anim_out")
                    self._anim_out.stop()
                    self._anim_out.setStartValue(cur_pos)
                    self._anim_out.setEndValue(end_pos)
                    def _on_finished():
                        try:
                            print("[Notification] anim_out finished")
                        except Exception:
                            pass
                        try:
                            self.hide()
                        except Exception:
                            pass
                    try:
                        self._anim_out.finished.disconnect()
                    except Exception:
                        pass
                    self._anim_out.finished.connect(_on_finished)
                    self._anim_out.start()
                except Exception:
                    try:
                        self.hide()
                    except Exception:
                        pass
            else:
                try:
                    self.hide()
                except Exception:
                    pass
        except Exception:
            try:
                self.hide()
            except Exception:
                pass

    def _tick (self ):
        self ._remaining -=self ._timer .interval ()
        if self ._remaining <=0 :
            self ._timer .stop ()
            try :

                try :
                    self .hide_with_animation ()
                except Exception :
                    self .hide ()
            except Exception :
                pass 
            return 
        try :
            self .progress .setValue (self ._remaining )
        except Exception :
            pass 

    def show_error (self ,text :str ,duration_ms :int =2200 ):
        """Mostrar la notificación con estilo de error (fondo rojo, texto blanco)."""
        try :

            old_style =self .text_label .styleSheet ()
            old_icon_style =self .icon_label .styleSheet ()




            try :

                self .icon_label .setStyleSheet ("border-radius:18px; background: #e74c3c; color: white; font-weight:700; text-align:center; border:1px solid rgba(0,0,0,0.06);")

                try :
                    self .icon_label .setText ("✖")
                except Exception :
                    self .icon_label .setText ("X")
                self .text_label .setStyleSheet ("color: #ffffff; font: 600 14px 'Avenir, Segoe UI';")
                self .progress .setStyleSheet ("QProgressBar{background:rgba(255,255,255,0.12); border-radius:3px;} QProgressBar::chunk{background:#ff6b6b; border-radius:3px;}")
            except Exception :
                pass 

            self .show_for (text ,duration_ms )


            def _restore ():

                try :
                    self .text_label .setStyleSheet (old_style )
                except Exception :
                    pass 

            QTimer .singleShot (duration_ms +50 ,_restore )
        except Exception :
            try :
                self .show_for (text ,duration_ms )
            except Exception :
                pass 

class PlayStatusWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("playStatusSquare")
        self.setFixedSize(450, 160)
        
        # Contenedor de imagen cuadrado más grande para evitar recortes
        self._bg_label = QLabel(self)
        self._bg_label.setGeometry(QRect(0, 0, 160, 160))
        self._bg_label.setStyleSheet("background:transparent;")
        
        inst_path = resource_path("instacia3.png")
        if inst_path and os.path.exists(inst_path):
            pm_orig = QPixmap(inst_path)
            # Escalar a tamaño fijo sin expandir para evitar recortes
            pm = pm_orig.scaled(160, 160, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            self._bg_label.setPixmap(pm)
            self._bg_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        else:
            self._bg_label.setStyleSheet("background:#444; color:white; font-weight:700;")
            self._bg_label.setText("?")

        self._title = QLabel("Hardcore", self)
        self._title.setGeometry(QRect(168, 26, 270, 34))
        self._title.setStyleSheet("color:white; font:700 23px 'Segoe UI';")
        self._subtitle = QLabel("", self)
        self._subtitle.setGeometry(QRect(168, 64, 270, 28))
        self._subtitle.setStyleSheet("color:#ddd; font:600 17px 'Segoe UI';")
        self._time = QLabel("", self)
        self._time.setGeometry(QRect(168, 94, 270, 22))
        self._time.setStyleSheet("color:#aaa; font:500 14px 'Segoe UI';")

        self._progress = QProgressBar(self)
        self._progress.setGeometry(QRect(168, 126, 270, 12))
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setTextVisible(False)
        self._progress.setStyleSheet("QProgressBar{background:rgba(255,255,255,0.15); border-radius:6px;} QProgressBar::chunk{background:#2ecc71; border-radius:6px;}")

        self._started_ts: Optional[float] = None
        self._state = "idle"  # idle|downloading|playing
        self.hide()

    def set_idle(self):
        self._state = "idle"
        self._subtitle.setText("")
        self._time.setText("")
        self._progress.hide()
        self.hide()

    def set_downloading(self, stage: str, percent: int = 0, eta_secs: Optional[int] = None):
        percent = max(0, min(100, percent))
        self._state = "downloading"
        self._subtitle.setText(stage)
        if self._started_ts is None:
            self._started_ts = time.time()
        elapsed = int(time.time() - self._started_ts)
        eta_txt = "" if eta_secs is None else f"ETA {eta_secs}s"
        self._time.setText(f"{elapsed:02d}s {eta_txt}".strip())
        self._progress.show()
        self._progress.setValue(percent)
        self.show()

    def set_playing(self):
        self._state = "playing"
        self._subtitle.setText("Playing")
        self._time.setText("")
        self._progress.hide()
        self.show()

    def update_progress(self, percent: int, stage: Optional[str] = None, eta_secs: Optional[int] = None):
        if self._state != "downloading":
            return
        if stage:
            self._subtitle.setText(stage)
        self.set_downloading(self._subtitle.text(), percent, eta_secs)

class MapWidget (QWidget ):
    def __init__ (self ,*args ,**kwargs ):
        super ().__init__ (*args ,**kwargs )
        bg_path =resource_path (BACKGROUND_FILE )
        self .bg :Optional [QPixmap ]=QPixmap (bg_path )if os .path .exists (bg_path )else None 

        self ._bg_filename =BACKGROUND_FILE if os .path .exists (bg_path )else None 
        self .setMinimumSize (900 ,480 )
        try:
            # allow the MapWidget to expand to fill available space when the window is resized/maximized
            self.setSizePolicy(QSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding))
        except Exception:
            pass


        lay =QVBoxLayout (self )
        lay .setContentsMargins (0 ,0 ,0 ,0 )
        lay .setSpacing (0 )

        # compute main_window early so nested functions/closures can reference it
        main_window = self.parent() if self.parent() is not None else self.window()
        self._launcher_owner = None

        try:
            if main_window is not None and any(
                hasattr(main_window, attr) for attr in ("get_auth_session", "ensure_minecraft_session")
            ):
                self._launcher_owner = main_window
        except Exception:
            self._launcher_owner = None


        try:
            if not globals().get('USE_NATIVE_TITLEBAR', False):
                if not USE_NATIVE_TITLEBAR:
                    self .titleBar = TitleBar(self)
                else:
                    self .titleBar = None
                main_window = self.parent() if self.parent() is not None else self.window()
                if main_window is not None:
                    try:
                        self .titleBar .minimizeRequested .connect (lambda :main_window .showMinimized ()if hasattr (main_window ,'showMinimized')else None )
                        self .titleBar .closeRequested .connect (lambda :main_window .close ()if hasattr (main_window ,'close')else None )
                        self .titleBar .maximizeRequested .connect (lambda :main_window .toggle_max_restore ()if hasattr (main_window ,'toggle_max_restore')else None )
                    except Exception:
                        pass
            else:
                self .titleBar = None
        except Exception:
            self .titleBar = None

        if getattr(self, 'titleBar', None) is not None:
            lay .addWidget (self .titleBar )



        center =QWidget ()
        c_layout =QHBoxLayout (center )

        c_layout .setContentsMargins (0 ,0 ,0 ,0 )
        c_layout .setSpacing (0 )


        left_bar =QWidget ()
        left_bar .setObjectName ("leftBar")
        left_bar .setFixedWidth (84 )

        left_bar .setSizePolicy (QSizePolicy (QSizePolicy .Policy .Fixed ,QSizePolicy .Policy .Expanding ))
        left_bar .setContentsMargins (0 ,0 ,0 ,0 )

        left_bar .setStyleSheet ("QWidget#leftBar { background: rgba(14,14,14,128); }")



        lb_layout =QVBoxLayout (left_bar )

        lb_layout .setContentsMargins (8 ,6 ,8 ,0 )
        lb_layout .setSpacing (10 )



        preferred =[resource_path ("instacia1.png"),resource_path ("instacia3.png")]
        candidates =[]
        for p in preferred :
            try :
                if os .path .exists (p ):
                    candidates .append (p )
            except Exception :
                pass 


        if len (candidates )<2 :
            try :
                base =os .path .dirname (os .path .abspath (sys .argv [0 ]))or os .path .abspath (".")
                for fname in os .listdir (base ):
                    if fname .lower ().endswith (('.png','.jpg','.jpeg','.bmp','.gif')):
                        full =os .path .join (base ,fname )
                        if full not in candidates :
                            candidates .append (full )
                    if len (candidates )>=2 :
                        break 
            except Exception :
                pass 


        # instance buttons (ensure instacia1 is first/above instacia3)
        self .inst_buttons =[]
        preferred_names = ["instacia1.png", "instacia3.png"]
        for i, name in enumerate(preferred_names):
            # creating instance button
            img_path = resource_path(name)
            # fallback to candidates list collected earlier if the specific resource is missing
            if not os.path.exists(img_path):
                try:
                    if i < len(candidates):
                        img_path = candidates[i]
                except Exception:
                    pass
            btn = RoundIconButton(img_path if img_path and os.path.exists(img_path) else None, size=64, tooltip="", padding=4)
            try:
                btn.setObjectName(f"inst_btn_{i+1}")
            except Exception:
                pass
            try:
                # ensure the button is parented to the left bar so it's placed correctly
                try:
                    btn.setParent(left_bar)
                except Exception:
                    pass
                btn.show()
            except Exception:
                pass
            # keep button behavior default (no instrumentation)

            if i == 0:
                # robust handler: try to call parent's open_instances(), otherwise show instancesWidget directly
                def _on_inst0_click(_checked=False):
                    try:
                        # determine main window at click time
                        mw = self.parent() if self.parent() is not None else self.window()
                        if mw is None:
                            try:
                                mw = QApplication.instance().activeWindow()
                            except Exception:
                                mw = None

                        if mw is not None:
                            if hasattr(mw, 'open_instances'):
                                try:
                                    mw.open_instances()
                                    return
                                except Exception:
                                    pass
                            # fallback: show instancesWidget directly
                            try:
                                if hasattr(mw, 'instancesWidget') and mw.instancesWidget is not None:
                                    mw.instancesWidget.show()
                                    mw.instancesWidget.raise_()
                                    mw.instancesWidget.setFocus()
                                    return
                            except Exception:
                                pass
                        print('instancia 1 clicked (could not open InstancesWidget)')
                    except Exception:
                        pass

                btn.clicked.connect(_on_inst0_click)
                # style the first button as selected
                try:
                    btn.setStyleSheet("background: transparent; border: 3px solid #3aa8ff; border-radius:8px;")
                except Exception:
                    pass
            else:
                # secondary instance: change background when clicked
                btn.clicked.connect(lambda _checked=False, fn="fondoinstacia3.png": self.set_background_image(fn))
                btn.clicked.connect(lambda _checked=False, idx=i: print(f"Instacia button {idx+1} clicked"))

            self .inst_buttons.append(btn)
            # add buttons in order so instacia1 remains above instacia3
            try:
                if i == 0:
                    # add a small top spacing so the first button sits lower
                    lb_layout.addSpacing(12)
            except Exception:
                pass
            lb_layout.addWidget(btn, 0, Qt.AlignmentFlag .AlignHCenter)
            # add extra spacing after the first button so the second appears lower
            try:
                if i == 0:
                    # adjust px as needed (18px works as a visible separation)
                    lb_layout.addSpacing(38)
            except Exception:
                pass

            # note: image used (None if not found)

        try :
            # make both buttons visible by default; keep the first visually selected
            for idx ,b in enumerate (self .inst_buttons ):
                try:
                    b.setVisible(True)
                    # keep button 0 with blue border, but ensure button 1 stays transparent (no blue)
                    if idx == 0:
                        try:
                            b.setStyleSheet("background: transparent; border: 3px solid #3aa8ff; border-radius:8px;")
                        except Exception:
                            pass
                    else:
                        try:
                            # force no border / transparent background for secondary instances
                            b.setStyleSheet("background: transparent; border: none;")
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception :
            pass 


        lb_layout .addStretch ()




        self ._floating =QWidget (self )
        try :
            self ._floating .setAttribute (Qt .WidgetAttribute .WA_TransparentForMouseEvents ,False )
        except Exception :
            pass 
        fv =QVBoxLayout (self ._floating )
        fv .setContentsMargins (6 ,6 ,6 ,6 )
        fv .setSpacing (8 )




        self ._small_avatar =RoundIconButton (None ,size =52 ,tooltip ="",padding =2 )

        self ._small_avatar .setStyleSheet (f"""
            QPushButton {{
                background: transparent;
                border: 4px solid #3aa8ff;
                border-radius: {52//2}px;
                padding: 0;
            }}
            QPushButton:hover {{ background: rgba(58,168,255,0.06); }}
        """)
        fv .addWidget (self ._small_avatar ,0 ,Qt .AlignmentFlag .AlignHCenter )


        try :
            self ._floating .adjustSize ()
            self ._floating .setFixedSize (self ._floating .sizeHint ())
            self ._floating .raise_ ()
        except Exception :
            pass 




        if main_window is not None and hasattr (main_window ,"avatarReady"):
            try :
                main_window .avatarReady .connect (self ._on_avatar_ready )
            except Exception :
                pass 


        def _on_small_avatar_clicked ():
            try :
                # Si NO hay sesión, permitir al usuario establecer un nametag local
                main_win = self.parent() if self.parent() is not None else self.window()
                if main_win is not None and hasattr(main_win, '_username') and (getattr(main_win, '_username') == 'Sin sesión' or not getattr(main_win, '_username')):
                    try:
                        from PyQt6.QtWidgets import QInputDialog
                        try:
                            from nametag_manager import get_nametag, set_nametag
                        except Exception:
                            get_nametag = lambda: None
                            set_nametag = lambda v: False

                        current = get_nametag() or ''
                        text, ok = QInputDialog.getText(self, APP_TITLE, 'Introduce tu nametag local (máx 16 chars):', QLineEdit.Normal, current)
                        if ok:
                            new_name = (text or '').strip()
                            if new_name:
                                try:
                                    saved = set_nametag(new_name)
                                except Exception:
                                    saved = False
                                if saved:
                                    try:
                                        main_win._username = new_name
                                    except Exception:
                                        pass
                                    try:
                                        main_win._used_local_nametag = True
                                    except Exception:
                                        pass
                                    try:
                                        if hasattr(main_win, 'save_config'):
                                            main_win.save_config()
                                    except Exception:
                                        pass
                                    try:
                                        if hasattr(main_win, 'load_profile_picture'):
                                            main_win.load_profile_picture(new_name)
                                    except Exception:
                                        pass
                                    try:
                                        if hasattr(main_win, 'btn_profile'):
                                            short = new_name if len(new_name) <= 12 else new_name[:11] + '…'
                                            main_win.btn_profile.setText(short)
                                            main_win.btn_profile.setToolTip(f"Local nametag: {new_name}")
                                    except Exception:
                                        pass
                                    return
                    except Exception:
                        pass

                # Si hay sesión (o el usuario no quiso establecer nametag), proceder al logout habitual
                resp = QMessageBox.question(self, APP_TITLE, "¿Cerrar sesión?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if resp != QMessageBox.StandardButton.Yes:
                    return
                if main_win is None:
                    return

                try:
                    if hasattr(main_win, '_username'):
                        main_win._username = 'Sin sesión'
                except Exception:
                    pass
                try:
                    if hasattr(main_win, 'update_auth_session'):
                        main_win.update_auth_session({})
                except Exception:
                    pass

                try:
                    if hasattr(main_win, 'mapWidget') and hasattr(main_win.mapWidget, 'inst_buttons'):
                        try:
                            for idx, b in enumerate(main_win.mapWidget.inst_buttons):
                                try:
                                    b.setVisible(True if idx == 0 else False)
                                except Exception:
                                    pass
                        except Exception:
                            pass
                except Exception:
                    pass

                try:
                    if hasattr(main_win, 'save_config'):
                        main_win.save_config()
                except Exception:
                    pass

                try:
                    if hasattr(main_win, 'btn_profile'):
                        main_win.btn_profile.setIcon(QIcon())
                        main_win.btn_profile.setText('Sin sesión')
                except Exception:
                    pass

                try:
                    placeholder = None
                    if hasattr(main_win, 'build_placeholder_avatar'):
                        placeholder = main_win.build_placeholder_avatar('?')
                    if placeholder is None:
                        placeholder = QPixmap(48, 48)
                        placeholder.fill(Qt.GlobalColor.transparent)
                    self._small_avatar.setIcon(QIcon(placeholder))
                    try:
                        self._small_avatar.setIconSize(placeholder.size())
                    except Exception:
                        pass
                except Exception:
                    pass

                try:
                    if hasattr(main_win, 'switch_to_main'):
                        main_win.switch_to_main()
                except Exception:
                    pass
                try:
                    if hasattr(main_win, 'open_login'):
                        main_win.open_login()
                except Exception:
                    pass
            except Exception :
                pass 

        def _perform_logout ():
            try :
                main_win =self .parent ()if self .parent ()is not None else self .window ()
                if main_win is None :
                    return 
                try :
                    if hasattr (main_win ,"_username"):
                        main_win ._username ="Sin sesión"
                except Exception :
                    pass 
                try:
                    if hasattr(main_win, 'update_auth_session'):
                        main_win.update_auth_session({})
                except Exception:
                    pass
                try :
                    if hasattr (main_win ,"mapWidget")and hasattr (main_win .mapWidget ,"inst_buttons"):
                        for idx ,b in enumerate (main_win .mapWidget .inst_buttons ):
                            try :
                                b .setVisible (True if idx ==0 else False )
                            except Exception :
                                pass 
                except Exception :
                    pass 
                try :
                    if hasattr (main_win ,"save_config"):
                        main_win .save_config ()
                except Exception :
                    pass 
                try :
                    if hasattr (main_win ,"btn_profile"):
                        main_win .btn_profile .setIcon (QIcon ())
                        main_win .btn_profile .setText ("Sin sesión")
                except Exception :
                    pass 
                try :
                    placeholder =None 
                    if hasattr (main_win ,"build_placeholder_avatar"):
                        placeholder =main_win .build_placeholder_avatar ("?")
                    if placeholder is None :
                        placeholder =QPixmap (48 ,48 )
                        placeholder .fill (Qt .GlobalColor .transparent )
                    self ._small_avatar .setIcon (QIcon (placeholder ))
                    try :
                        self ._small_avatar .setIconSize (placeholder .size ())
                    except Exception :
                        pass 
                except Exception :
                    pass 
                try :
                    if hasattr (main_win ,"switch_to_main"):
                        main_win .switch_to_main ()
                except Exception :
                    pass 
                try :
                    if hasattr (main_win ,"open_login"):
                        main_win .open_login ()
                except Exception :
                    pass 
            except Exception :
                pass 

        def _on_small_avatar_clicked ():
            try :
                menu =QMenu (self )
                wa =QWidgetAction (menu )
                btn =QPushButton ("Log out")
                btn .setCursor (Qt .CursorShape .PointingHandCursor )
                btn .setStyleSheet ("QPushButton { color: #e74c3c; background: transparent; border: none; padding:6px 12px; font-weight:600; }")
                btn .clicked .connect (lambda :(menu .hide (),_perform_logout ()))
                wa .setDefaultWidget (btn )
                menu .addAction (wa )
                pos =self ._small_avatar .mapToGlobal (QPoint (0 ,self ._small_avatar .height ()))
                menu .exec (pos )
            except Exception :
                pass 

        self ._small_avatar .clicked .connect (_on_small_avatar_clicked )



        content_area =QWidget ()
        content_layout =QVBoxLayout (content_area )
        content_layout .setContentsMargins (0 ,0 ,0 ,0 )
        content_layout .setSpacing (0 )
        content_layout .addStretch ()

        logo_label =QLabel ()
        logo_label .setAlignment (Qt .AlignmentFlag .AlignCenter )
        logo_path =resource_path ("logo_allio.png")
        if os .path .exists (logo_path ):
            logo_pm =QPixmap (logo_path ).scaled (520 ,260 ,Qt .AspectRatioMode .KeepAspectRatio ,Qt .TransformationMode .SmoothTransformation )
            logo_label .setPixmap (logo_pm )
        else :

            logo_label .setText ("")
        content_layout .addWidget (logo_label ,alignment =Qt .AlignmentFlag .AlignCenter )
        content_layout .addStretch ()


        c_layout .addWidget (left_bar ,0 )
        c_layout .addWidget (content_area ,1 )

        lay .addWidget (center ,1 )

        # ensure left_bar is visible and above other widgets
        try:
            left_bar.show()
            left_bar.raise_()
        except Exception:
            pass

        # debug: print visibility of instance buttons after layout
        try:
            for idx, b in enumerate(getattr(self, 'inst_buttons', [])):
                try:
                    print(f"[DEBUG] after layout: inst_button {idx+1} visible={b.isVisible()} enabled={b.isEnabled()} objectName={b.objectName()}")
                    b.show()
                    b.raise_()
                except Exception:
                    pass
        except Exception:
            pass



        self .play_btn =QPushButton ("Play",self )
        self .play_btn .setObjectName ("playBtnFloating")
        self .play_btn .setCursor (Qt .CursorShape .PointingHandCursor )
        # make the play button wider with rounded corners (rectangular pill)
        self .play_btn .setFixedHeight (56 )
        self .play_btn .setMinimumWidth (420 )

        self .play_btn .setStyleSheet ("""
            QPushButton#playBtnFloating {
                /* slightly more opaque background for better legibility */
                background: rgba(255,255,255,0.18);
                color: white;
                font: 700 20px 'Avenir, Segoe UI';
                border-radius: 14px; /* pill-like rounded corners */
                padding-left: 36px;
                padding-right: 36px;
                text-align: center;
            }
            QPushButton#playBtnFloating:hover { background: rgba(255,255,255,0.24); }
            QPushButton#playBtnFloating:pressed { background: rgba(255,255,255,0.28); }
        """)

        self .play_btn .clicked .connect (self .launch_minecraft_java )
        
        # Verificar estado de Java 21 y actualizar interfaz
        self.update_java_status()

        # Cuadro de estado para reemplazar el botón Play cuando se está lanzando/descargando
        try:
            self.play_tile = PlayStatusWidget(self)
            self.play_tile.hide()
        except Exception:
            self.play_tile = None

    def _resolve_launcher_owner(self) -> Optional[Any]:
        """Locate the main launcher window to delegate auth/session helpers."""
        if getattr(self, "_launcher_owner", None) is not None:
            owner = self._launcher_owner
            if any(hasattr(owner, attr) for attr in ("get_auth_session", "ensure_minecraft_session")):
                return owner

        candidate = None
        try:
            candidate = self.parentWidget()
        except Exception:
            candidate = None
        if candidate is None:
            try:
                candidate = self.window()
            except Exception:
                candidate = None

        hops = 0
        while candidate is not None and hops < 8:
            if any(hasattr(candidate, attr) for attr in ("get_auth_session", "ensure_minecraft_session")):
                self._launcher_owner = candidate
                return candidate
            try:
                candidate = candidate.parentWidget()
            except Exception:
                candidate = None
            hops += 1

        try:
            app_inst = QApplication.instance()
            if app_inst is not None:
                active = app_inst.activeWindow()
                if active is not None and any(hasattr(active, attr) for attr in ("get_auth_session", "ensure_minecraft_session")):
                    self._launcher_owner = active
                    return active
        except Exception:
            pass

        return None

    def get_auth_session(self) -> dict:
        """Delegate to the launcher window auth session if available."""
        owner = self._resolve_launcher_owner()
        if owner is not None and hasattr(owner, "get_auth_session"):
            try:
                return dict(owner.get_auth_session())
            except Exception as exc:
                print(f"[Allio MapWidget] Aviso delegando get_auth_session: {exc}")
        return {}

    def ensure_minecraft_session(self, force_refresh: bool = False) -> dict:
        """Delegate token refresh to the launcher window if possible."""
        owner = self._resolve_launcher_owner()
        if owner is not None and hasattr(owner, "ensure_minecraft_session"):
            try:
                return owner.ensure_minecraft_session(force_refresh=force_refresh)
            except Exception as exc:
                print(f"[Allio MapWidget] Aviso delegando ensure_minecraft_session: {exc}")
        return {}

    def update_java_status(self):
        """Actualiza el estado de Java 21 en la interfaz"""
        try:
            java_21_path = self.find_existing_java21()
            
            if java_21_path:
                # Java 21 disponible - botón normal
                self.play_btn.setText("Jugar")
                self.play_btn.setToolTip(f"Java 21 encontrado: {java_21_path}\nHaz clic para lanzar Minecraft 1.21.10 con Fabric")
                self.play_btn.setEnabled(True)
                print(f"[Allio] OK Java 21 disponible: {java_21_path}")
            else:
                # Java 21 no disponible - indicar instalación
                self.play_btn.setText("Jugar")
                # No mostrar el aviso de requisito Java al pasar el ratón
                try:
                    self.play_btn.setToolTip("")
                except Exception:
                    pass
                self.play_btn.setEnabled(True)
                print("[Allio] AVISO Java 21 no encontrado - requerira instalacion")
                
        except Exception as e:
            print(f"[Allio] Error verificando Java: {e}")
            self.play_btn.setText("JUGAR")
            self.play_btn.setEnabled(True)
    
    def find_existing_java21(self):
        """Busca Java 21 o superior existente sin mostrar diálogos"""
        import glob
        
        # Buscar todas las versiones de Java (incluyendo 21, 22, 23, 24, 25, etc.)
        java_paths = [
            r"C:\Program Files\Java\jdk-*\bin\java.exe",
            r"C:\Program Files\Java\jre-*\bin\java.exe", 
            r"C:\Program Files\Eclipse Adoptium\jdk-*\bin\java.exe",
            r"C:\Program Files\Microsoft\jdk-*\bin\java.exe",
            r"C:\Program Files\OpenJDK\jdk-*\bin\java.exe",
            r"C:\Program Files\Java\jdk-21-allio\bin\java.exe"  # Nuestra instalación
        ]
        
        # Buscar instalaciones existentes
        for pattern in java_paths:
            matches = glob.glob(pattern)
            for match in matches:
                if self.verify_java21_or_higher(match):
                    return match
        
        return None




    def microsoft_login(self):
        """Inicia el proceso de autenticación con Microsoft"""
        if Flask is None or request is None:
            QMessageBox.warning(
                self,
                "Dependencia faltante",
                "No se encontró Flask. Instálalo con 'pip install flask' para iniciar sesión con Microsoft."
            )
            return None
        
        # Verificar conexión a Internet
        try:
            test_response = requests.get("https://login.live.com", timeout=5)
            if test_response.status_code >= 500:
                raise Exception("Servidor no disponible")
        except Exception as e:
            QMessageBox.warning(
                self,
                "Sin conexión",
                f"No se pudo conectar a los servidores de Microsoft.\n\n"
                f"Verifica tu conexión a Internet e intenta de nuevo.\n\n"
                f"Error: {str(e)}"
            )
            return None
        
        # Generar code verifier y challenge para PKCE
        code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')

        # Configurar el servidor Flask para recibir el código
        app = Flask(__name__)
        auth_code = None
        auth_completed = threading.Event()
        import secrets
        state = secrets.token_urlsafe(16)

        @app.route('/redirect', methods=['GET', 'POST'])
        def redirect_handler():
            nonlocal auth_code
            try:
                # logear request para debugging
                try:
                    print(f"[Allio OAuth] Redirect request URL: {request.url}")
                    print(f"[Allio OAuth] Redirect args: {dict(request.args)}")
                    _append_run_log(f"Redirect request: {request.url} | args={dict(request.args)}")
                except Exception:
                    pass

                # aceptar GET o POST
                if request.method == 'POST':
                    code = request.form.get('code')
                    state_received = request.form.get('state')
                    error_received = request.form.get('error')
                else:
                    code = request.args.get('code')
                    state_received = request.args.get('state')
                    error_received = request.args.get('error')

                if error_received:
                    print(f"[Allio OAuth] Error recibido en redirect: {error_received}")
                    _append_run_log(f"OAuth error: {error_received}")
                    auth_code = '__error__:' + str(error_received)
                    auth_completed.set()
                    return "Error received. You can close this window."

                if state_received and state_received != state:
                    print(f"[Allio OAuth] WARNING: state no coincide (recibido={state_received} guardado={state})")
                    _append_run_log(f"State mismatch: received={state_received} expected={state}")

                if code:
                    auth_code = code
                    _append_run_log(f"Code captured: {code[:20]}...")
                    auth_completed.set()
                return "Success! You can now close this window and go back to the Allio Launcher."
            except Exception as e:
                print(f"[Allio OAuth] Error en redirect_handler: {e}")
                _append_run_log(f"redirect_handler exception: {e}")
                return "Error processing redirect.", 500

        # Iniciar servidor en un hilo separado (forzar bind a 127.0.0.1 y desactivar reloader)
        server = threading.Thread(target=lambda: app.run(host='127.0.0.1', port=MS_FLASK_PORT, debug=False, use_reloader=False))
        server.daemon = True
        server.start()

        # Construir URL de autorización (usar endpoint moderno y enviar state + prompt)
        # Forzamos una redirect URI normalizada para evitar mismatches con Azure
        redirect_val = _get_normalized_redirect()
        params = {
            "client_id": MS_CLIENT_ID,
            "response_type": "code",
            "redirect_uri": redirect_val,
            "response_mode": "query",
            "scope": MS_OAUTH_SCOPE,
            "state": state,
            "prompt": "consent",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        auth_url = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?" + urllib.parse.urlencode(params)
        _append_run_log(f"Auth URL: {auth_url}")
        print(f"[Allio OAuth] Auth URL: {auth_url}")

        # Abrir navegador
        try:
            webbrowser.open(auth_url)
        except Exception as e:
            QMessageBox.warning(
                self,
                "Error abriendo navegador",
                f"No se pudo abrir el navegador automáticamente.\n\n"
                f"Copia este enlace y ábrelo manualmente:\n\n{auth_url}\n\n"
                f"Error: {str(e)}"
            )
            return None

        # Esperar respuesta
        auth_completed.wait(timeout=300)
        if not auth_code:
            QMessageBox.information(
                self,
                "Inicio de sesión cancelado",
                "No se recibió el código de autenticación.\n\n"
                "El inicio de sesión fue cancelado o expiró.\n"
                "Intenta de nuevo si deseas iniciar sesión."
            )
            return None

        # Intercambiar código por tokens
        token_data = {
            'client_id': MS_CLIENT_ID,
            'code': auth_code,
            'code_verifier': code_verifier,
            'grant_type': 'authorization_code',
            'redirect_uri': MS_REDIRECT_URI
        }

        # Si el redirect nos devolvió un error explícito, abortar y mostrarlo
        try:
            if isinstance(auth_code, str) and auth_code.startswith('__error__:'):
                err = auth_code.split(':', 1)[1]
                print(f"[Allio] OAuth error: {err}")
                _append_run_log(f"OAuth error received before token exchange: {err}")
                QMessageBox.warning(self, "Error OAuth", f"OAuth error: {err}")
                return None
        except Exception:
            pass

        try:
            response = requests.post(MS_TOKEN_URL, data=token_data, timeout=20)
            _append_run_log(f"Token response status: {response.status_code}")
            if response.status_code != 200:
                error_text = response.text
                print(f"[Allio] Error intercambiando código: {response.status_code} -> {error_text}")
                _append_run_log(f"Token exchange error: {response.status_code} -> {error_text}")
                QMessageBox.warning(
                    self,
                    "Error de autenticación",
                    f"No se pudo obtener el token de acceso de Microsoft.\n\n"
                    f"Código de error: {response.status_code}\n"
                    f"Intenta iniciar sesión de nuevo."
                )
                return None
            ms_tokens = response.json()
            _append_run_log(f"Token payload keys: {list(ms_tokens.keys())}")
            if not ms_tokens.get('access_token'):
                print(f"[Allio] Respuesta sin access_token: {ms_tokens}")
                _append_run_log(f"No access_token in response: {ms_tokens}")
                QMessageBox.warning(
                    self,
                    "Error de autenticación",
                    "La respuesta de Microsoft no contiene un token de acceso válido.\n"
                    "Intenta iniciar sesión de nuevo."
                )
                return None
        except requests.exceptions.RequestException as e:
            print(f"[Allio] Error intercambiando código por tokens: {e}")
            _append_run_log(f"Token exchange request exception: {e}")
            QMessageBox.warning(
                self,
                "Error de conexión",
                f"No se pudo conectar a los servidores de Microsoft.\n\n"
                f"Error: {str(e)}\n\n"
                f"Verifica tu conexión a Internet e intenta de nuevo."
            )
            return None
        except Exception as e:
            print(f"[Allio] Error inesperado: {e}")
            QMessageBox.warning(
                self,
                "Error",
                f"Ocurrió un error inesperado durante la autenticación.\n\n"
                f"Error: {str(e)}"
            )
            return None

        # Autenticar con Xbox Live
        xbox_auth_data = {
            'Properties': {
                'AuthMethod': 'RPS',
                'SiteName': 'user.auth.xboxlive.com',
                'RpsTicket': f'd={ms_tokens["access_token"]}'
            },
            'RelyingParty': 'http://auth.xboxlive.com',
            'TokenType': 'JWT'
        }

        try:
            response = requests.post(XBOX_USER_AUTH_URL, json=xbox_auth_data, timeout=20)
            if response.status_code != 200:
                print(f"[Allio] Error Xbox auth: {response.status_code} -> {response.text}")
                QMessageBox.warning(
                    self,
                    "Error de Xbox Live",
                    f"No se pudo autenticar con Xbox Live.\n\n"
                    f"Código de error: {response.status_code}\n"
                    f"Asegúrate de que tu cuenta de Microsoft tenga Xbox Live configurado."
                )
                return None
            xbox_data = response.json()
            xbox_token = xbox_data.get('Token')
            user_hash = xbox_data.get('DisplayClaims', {}).get('xui', [{}])[0].get('uhs', '')
            
            if not xbox_token or not user_hash:
                print(f"[Allio] Respuesta Xbox incompleta: {xbox_data}")
                QMessageBox.warning(
                    self,
                    "Error de Xbox Live",
                    "No se pudo obtener el token de Xbox Live.\n"
                    "Verifica que tu cuenta tenga Xbox Live configurado correctamente."
                )
                return None
        except requests.exceptions.RequestException as e:
            print(f"[Allio] Error Xbox auth: {e}")
            QMessageBox.warning(
                self,
                "Error de conexión",
                f"No se pudo conectar a Xbox Live.\n\n"
                f"Error: {str(e)}"
            )
            return None
        except Exception as e:
            print(f"[Allio] Error Xbox auth: {e} -> {getattr(response, 'text', '') if 'response' in locals() else ''}")
            return None

        # Obtener token XSTS
        xsts_data = {
            'Properties': {
                'SandboxId': 'RETAIL',
                'UserTokens': [xbox_token]
            },
            'RelyingParty': 'rp://api.minecraftservices.com/',
            'TokenType': 'JWT'
        }

        try:
            response = requests.post(XBOX_XSTS_URL, json=xsts_data, timeout=20)
            if response.status_code != 200:
                error_data = {}
                try:
                    error_data = response.json()
                except Exception:
                    pass
                xerr = error_data.get('XErr')
                if xerr == 2148916233:
                    QMessageBox.warning(
                        self,
                        "Cuenta sin Xbox",
                        "Esta cuenta de Microsoft no tiene una cuenta de Xbox Live.\n\n"
                        "Para jugar Minecraft, necesitas:\n"
                        "1. Crear una cuenta de Xbox (gratis)\n"
                        "2. Vincularla a tu cuenta de Microsoft\n"
                        "3. Tener Minecraft Java Edition"
                    )
                    return None
                elif xerr == 2148916238:
                    QMessageBox.warning(
                        self,
                        "Cuenta infantil",
                        "Esta cuenta está configurada como cuenta infantil.\n\n"
                        "Necesitas que un adulto te agregue a una familia Xbox\n"
                        "para poder jugar Minecraft."
                    )
                    return None
                print(f"[Allio] Error XSTS: código {response.status_code}, XErr={xerr}")
                return None
            
            xsts_response = response.json()
            xsts_token = xsts_response.get('Token')
            # Obtener gamertag de XSTS
            xui = xsts_response.get('DisplayClaims', {}).get('xui', [{}])[0]
            gamertag = xui.get('gtg')
            
            if not xsts_token:
                print(f"[Allio] Error: respuesta XSTS sin token: {xsts_response}")
                return None
        except requests.exceptions.RequestException as e:
            print(f"[Allio] Error obteniendo XSTS token: {e} -> {getattr(response, 'text', '') if 'response' in locals() else ''}")
            return None

        # Autenticar con Minecraft
        minecraft_data = {
            'identityToken': f"XBL3.0 x={user_hash};{xsts_token}"
        }

        try:
            response = requests.post(MINECRAFT_LOGIN_URL, json=minecraft_data, timeout=20)
            if response.status_code != 200:
                print(f"[Allio] Error login Minecraft: {response.status_code} -> {response.text}")
                QMessageBox.warning(
                    self,
                    "Error de autenticación",
                    "No se pudo autenticar con Minecraft.\n\n"
                    "Verifica que tu cuenta tenga Minecraft Java Edition."
                )
                return None
            access_token = response.json().get('access_token')
            if not access_token:
                print(f"[Allio] Respuesta de Minecraft sin access_token: {response.text}")
                return None
        except Exception as e:
            print(f"[Allio] Error login Minecraft: {e} -> {getattr(response, 'text', '') if 'response' in locals() else ''}")
            return None

        # Obtener perfil de Minecraft
        headers = {'Authorization': f'Bearer {access_token}'}
        try:
            response = requests.get(MINECRAFT_PROFILE_URL, headers=headers, timeout=20)
            if response.status_code == 404:
                QMessageBox.warning(
                    self,
                    "Minecraft no encontrado",
                    "Esta cuenta de Microsoft no tiene Minecraft Java Edition.\n\n"
                    "Necesitas comprar Minecraft Java Edition para jugar.\n"
                    "Visita: https://www.minecraft.net/es-es/store/minecraft-java-bedrock-edition-pc"
                )
                return None
            response.raise_for_status()
            profile = response.json()
            if not profile.get('id') or not profile.get('name'):
                print(f"[Allio] Perfil de Minecraft incompleto: {profile}")
                QMessageBox.warning(
                    self,
                    "Perfil incompleto",
                    "No se pudo obtener el perfil completo de Minecraft.\n"
                    "Intenta cerrar sesión y volver a iniciarla."
                )
                return None
        except requests.exceptions.RequestException as e:
            print(f"[Allio] Error obteniendo perfil Minecraft: {e} -> {getattr(response, 'text', '') if 'response' in locals() else ''}")
            return None
        
        # Guardar datos de autenticación
        minecraft_username = profile.get('name', '')
        minecraft_uuid = profile.get('id', '')
        
        # Obtener XUID del usuario de Xbox
        xuid = xui.get('xid', '')
        
        # Formatear UUID con guiones
        uuid_no_dash = minecraft_uuid.replace('-', '')
        if len(uuid_no_dash) == 32:
            uuid_formatted = f"{uuid_no_dash[0:8]}-{uuid_no_dash[8:12]}-{uuid_no_dash[12:16]}-{uuid_no_dash[16:20]}-{uuid_no_dash[20:32]}"
        else:
            uuid_formatted = minecraft_uuid
        
        # Guardar sesión de autenticación
        auth_session = {
            'ms_access_token': ms_tokens.get('access_token', ''),
            'ms_refresh_token': ms_tokens.get('refresh_token', ''),
            'minecraft_token': access_token,
            'minecraft_username': minecraft_username,
            'minecraft_uuid': uuid_formatted,
            'minecraft_uuid_nodash': uuid_no_dash,
            'gamertag': gamertag or minecraft_username,
            'profile_name': gamertag or minecraft_username,
            'xuid': xuid,
            'ms_account_email': '',
            'client_token': str(uuid.uuid4()),
            'auth_source': 'microsoft_oauth',
            'updated_at': time.time(),
        }
        
        self.update_auth_session(auth_session)
        
        return {
            'access_token': access_token,
            'username': minecraft_username,
            'uuid': uuid_formatted,
            'gamertag': gamertag or minecraft_username,
            'email': '',
            'has_minecraft': profile is not None,
            'refresh_token': ms_tokens.get('refresh_token', ''),
            'xuid': xuid
        }

    def _build_offline_session(self, username: str) -> dict[str, object]:
        """Genera una sesión offline consistente a partir del nombre de usuario actual."""
        safe_username = _ensure_username(username)
        offline_uuid = uuid.uuid3(uuid.NAMESPACE_DNS, f"OfflinePlayer:{safe_username}")
        client_token = None
        owner = None
        try:
            resolver = getattr(self, "_resolve_launcher_owner", None)
            if callable(resolver):
                owner = resolver()
        except Exception:
            owner = None

        if owner is not None and hasattr(owner, "_client_token"):
            client_token = getattr(owner, "_client_token", None) or None

        if not client_token:
            client_token = getattr(self, "_client_token", None)

        if not client_token:
            client_token = uuid.uuid4().hex
        session = {
            'minecraft_username': safe_username,
            'profile_name': safe_username,
            'minecraft_uuid': str(offline_uuid),
            'minecraft_uuid_nodash': offline_uuid.hex,
            'minecraft_token': '0',
            'client_token': client_token,
            'auth_source': 'offline',
            'updated_at': time.time(),
        }
        if owner is not None and hasattr(owner, "_client_token"):
            try:
                if not getattr(owner, "_client_token", None):
                    owner._client_token = client_token
            except Exception:
                pass
        try:
            self._client_token = client_token
        except Exception:
            pass
        return session

    def launch_minecraft_java(self):
        """Lanza Minecraft Java Edition con la instancia Fabric Hardcore directamente (sin launcher oficial)"""
        try:
            # Helper para restaurar el botón Jugar y ocultar el tile de estado
            def _reset_play_ui():
                try:
                    if hasattr(self, 'play_tile') and self.play_tile:
                        self.play_tile.set_idle()
                    if hasattr(self, 'play_btn') and self.play_btn:
                        self.play_btn.show()
                except Exception:
                    pass

            # Activar estado visual de lanzamiento: mostrar "Playing Hardcore" INMEDIATAMENTE
            if hasattr(self, 'play_tile') and self.play_tile is not None:
                # Posicionar donde estaba el botón
                if hasattr(self, 'play_btn') and self.play_btn.isVisible():
                    self.play_tile.move(self.play_btn.pos())
                # Mostrar estado Playing enseguida como pidió el usuario
                print("[Allio DEBUG] Mostrando 'Playing Hardcore' al instante")
                self.play_tile.set_playing()
                self.play_tile.show()
                self.play_tile.raise_()
                if hasattr(self, 'play_btn'):
                    self.play_btn.hide()
                # Forzar procesamiento de eventos para mostrar el tile AHORA
                QApplication.processEvents()
            
            # Actualizar Discord RPC a estado "jugando"
            try:
                if hasattr(self, 'discord_rpc') and self.discord_rpc.connected:
                    username = getattr(self, '_username', None)
                    self.discord_rpc.set_playing("Hardcore", username)
            except Exception as e:
                print(f"[Discord RPC] Error actualizando presencia al lanzar: {e}")
            print("[Allio] ========================================")
            print("[Allio] INICIANDO LANZAMIENTO DE MINECRAFT")
            print("[Allio] ========================================")
            print(f"[Allio] Modo ejecutable: {getattr(sys, 'frozen', False)}")
            print(f"[Allio] Python executable: {sys.executable}")
            print(f"[Allio] Working directory: {os.getcwd()}")
            
            # Ruta de la instancia personalizada
            # Cuando se ejecuta desde .exe, PyInstaller extrae los recursos a sys._MEIPASS
            if getattr(sys, 'frozen', False):
                # Modo ejecutable - PyInstaller extrae recursos a _MEIPASS (carpeta temporal)
                # Pero para Minecraft necesitamos una carpeta persistente
                # Usar AppData del usuario
                appdata_allio = os.path.join(os.getenv('APPDATA'), 'AllioClient')
                instance_path = os.path.join(appdata_allio, "Hardcore Instace")
                print(f"[Allio] Modo .EXE detectado")
                print(f"[Allio] AppData Allio: {appdata_allio}")
                print(f"[Allio] Instance path: {instance_path}")
                
                # Si la instancia no existe en AppData, copiarla desde los recursos empaquetados
                if not os.path.exists(instance_path):
                    # Recursos empaquetados están en sys._MEIPASS
                    bundled_instance = os.path.join(sys._MEIPASS, "Hardcore Instace")
                    print(f"[Allio] Instancia no existe, buscando en: {bundled_instance}")
                    if os.path.exists(bundled_instance):
                        print(f"[Allio] Copiando instancia desde recursos empaquetados...")
                        os.makedirs(appdata_allio, exist_ok=True)
                        import shutil
                        shutil.copytree(bundled_instance, instance_path)
                        print(f"[Allio] Instancia copiada a: {instance_path}")
                    else:
                        QMessageBox.critical(self, "Error", 
                            f"No se encontró la instancia empaquetada en:\n{bundled_instance}\n\n"
                            "El ejecutable no incluye la carpeta 'Hardcore Instace'.")
                        _reset_play_ui()
                        return False
            else:
                # Modo script - usar ruta del proyecto
                base_dir = os.path.dirname(os.path.abspath(__file__))
                instance_path = os.path.join(base_dir, "Hardcore Instace")
            
            # Verificar que la instancia existe
            if not os.path.exists(instance_path):
                QMessageBox.critical(self, "Error", 
                    f"No se encontró la carpeta de la instancia:\n{instance_path}")
                _reset_play_ui()
                return False
            
            print(f"[Allio] Usando instancia en: {instance_path}")
            
            # Ruta de .minecraft (para assets, librerías, etc)
            minecraft_dir = os.path.join(os.getenv('APPDATA'), '.minecraft')
            
            # CRÍTICO: Validar y limpiar librerías ANTES de construir el classpath
            # Esto previene el error "duplicate ASM classes" que causa crash inmediato
            print("[Allio] Validando integridad de librerías...")
            try:
                # 1. Mover JARs corruptos
                moved = validate_and_cleanup_corrupt_jars(minecraft_dir)
                if moved:
                    moved_list = '\n'.join([m[0] for m in moved[:8]])
                    print(f"[Allio] JARs corruptos movidos: {len(moved)}")
                    QMessageBox.warning(self, "JARs corruptos detectados",
                        "Se detectaron archivos JAR corruptos y fueron movidos a '.minecraft/corrupt_libraries'.\n"
                        f"Archivos detectados: {len(moved)}\n\n" + moved_list +
                        "\n\nEl launcher los re-descargará automáticamente.")
                
                # 2. SIEMPRE ejecutar limpieza de duplicados (causa común del error ASM)
                print("[Allio] Ejecutando limpieza de versiones duplicadas...")
                duplicates = quarantine_duplicate_library_versions(minecraft_dir)
                if duplicates:
                    dup_list = '\n'.join(src for src, _ in duplicates[:8])
                    print(f"[Allio] ✓ Librerías duplicadas movidas: {len(duplicates)}")
                    print("[Allio] Esto evita el error 'duplicate ASM classes found on classpath'")
                    # Mostrar aviso solo si hay muchas duplicadas (>5)
                    if len(duplicates) > 5:
                        try:
                            QMessageBox.information(self, "Limpieza de librerías",
                                f"Se movieron {len(duplicates)} versiones antiguas de librerías a '.minecraft/duplicate_libraries'.\n\n"
                                "Esto previene el error 'duplicate ASM classes' que causa crash al iniciar.\n\n"
                                f"Primeros archivos:\n{dup_list}")
                        except Exception:
                            pass
                else:
                    print("[Allio] ✓ No se encontraron librerías duplicadas")
            except Exception as e:
                print(f"[Allio] ADVERTENCIA validando librerías: {e}")
                import traceback
                traceback.print_exc()
            # Versión de Fabric y Minecraft
            fabric_version = "fabric-loader-0.17.3-1.21.10"
            mc_base_version = fabric_version.split('-')[-1] if '-' in fabric_version else "1.21.10"

            # INSTALACIÓN AUTOMÁTICA DE FABRIC si no existe
            version_dir = os.path.join(minecraft_dir, "versions", fabric_version)
            fabric_jar = os.path.join(version_dir, f"{fabric_version}.jar")
            
            if not os.path.exists(fabric_jar):
                print(f"[Allio] Fabric {fabric_version} no encontrado, instalando...")
                # Cambiar de 'Playing' a modo descarga real
                try:
                    if self.play_tile:
                        self.play_tile.set_downloading("Downloading Minecraft Libraries", 5)
                    # Actualizar Discord RPC
                    if hasattr(self, 'discord_rpc') and self.discord_rpc.connected:
                        self.discord_rpc.set_downloading("Minecraft Libraries")
                except Exception:
                    pass
                try:
                    if minecraft_launcher_lib:
                        try:
                            if self.play_tile:
                                self.play_tile.set_downloading("Installing Minecraft Base", 15)
                        except Exception:
                            pass
                        # Instalar Minecraft vanilla primero si no existe
                        vanilla_jar = os.path.join(minecraft_dir, 'versions', mc_base_version, f"{mc_base_version}.jar")
                        if not os.path.exists(vanilla_jar):
                            print(f"[Allio] Instalando Minecraft {mc_base_version}...")
                            minecraft_launcher_lib.install.install_minecraft_version(mc_base_version, minecraft_dir)
                        
                        # Instalar Fabric
                        print(f"[Allio] Instalando Fabric Loader 0.17.3 para Minecraft {mc_base_version}...")
                        try:
                            if self.play_tile:
                                self.play_tile.set_downloading("Installing Fabric Loader", 45)
                        except Exception:
                            pass
                        minecraft_launcher_lib.fabric.install_fabric(mc_base_version, minecraft_dir, loader_version="0.17.3")
                        print(f"[Allio] OK Fabric instalado correctamente")
                        try:
                            if self.play_tile:
                                self.play_tile.set_downloading("Preparing Assets", 60)
                        except Exception:
                            pass
                    else:
                        QMessageBox.critical(self, "Error", 
                            f"Fabric no está instalado y no se puede instalar automáticamente.\n\n"
                            f"Por favor, instala Fabric Loader 0.17.3 para Minecraft {mc_base_version} "
                            "desde el launcher oficial de Minecraft.")
                        _reset_play_ui()
                        return False
                except Exception as install_err:
                    print(f"[Allio] Error instalando Fabric: {install_err}")
                    QMessageBox.critical(self, "Error instalando Fabric", 
                        f"No se pudo instalar Fabric automáticamente:\n{install_err}\n\n"
                        f"Por favor, instala Fabric Loader 0.17.3 para Minecraft {mc_base_version} "
                        "manualmente desde el launcher oficial.")
                    _reset_play_ui()
                    return False

            missing_assets, assets_info = check_minecraft_assets(version_hint=mc_base_version, max_missing=0, return_details=True)
            if missing_assets:
                print(f"[Allio] Detectados assets faltantes antes del lanzamiento: {missing_assets[:12]}")
                try:
                    if self.play_tile:
                        self.play_tile.set_downloading("Repairing Assets", 65)
                except Exception:
                    pass
                repaired = download_missing_minecraft_assets(
                    mc_base_version,
                    minecraft_dir,
                    missing_assets,
                    assets_info.get('objects_map') if isinstance(assets_info, dict) else None,
                )
                if repaired:
                    missing_assets, assets_info = check_minecraft_assets(version_hint=mc_base_version, max_missing=0, return_details=True)
                if missing_assets:
                    missing_preview = '\n'.join(missing_assets[:12])
                    index_path = assets_info.get('index_path') if isinstance(assets_info, dict) else None
                    if index_path:
                        print(f"[Allio] Index usado: {index_path}")
                    if assets_info.get('objects_dir'):
                        print(f"[Allio] objects_dir: {assets_info['objects_dir']}")
                    print(f"[Allio] Lista completa de faltantes: {missing_preview}")
                    try:
                        QMessageBox.warning(self, "Assets faltantes",
                            "Faltan archivos esenciales de Minecraft. Se canceló el lanzamiento para evitar la pantalla negra.\n"
                            "Se intentó restaurarlos automáticamente pero algunos siguen ausentes.\n\n"
                            "Acciones sugeridas:\n"
                            "  1. Ejecuta 'python repair_and_install_assets.py'.\n"
                            "  2. Abre el launcher oficial e inicia la versión 1.21.10.\n"
                            "  3. Verifica tu conexión a la red.\n\n"
                            f"Primeros archivos faltantes:\n{missing_preview}")
                    except Exception:
                        pass
                    _reset_play_ui()
                    return False

            # Buscar Java 21+ (ajusta si tu ruta es diferente)
            java_candidates = [
                r"C:\Program Files\Java\jdk-21\bin\java.exe",
                r"C:\Program Files\Java\jdk-25\bin\java.exe",
                r"C:\Program Files\Eclipse Adoptium\jdk-21*\bin\java.exe",
            ]
            
            # Buscar dinámicamente en Program Files
            try:
                java_base_dirs = [
                    r"C:\Program Files\Java",
                    r"C:\Program Files\Eclipse Adoptium",
                    r"C:\Program Files (x86)\Java",
                    r"C:\Program Files (x86)\Eclipse Adoptium"
                ]
                for base_dir in java_base_dirs:
                    if os.path.exists(base_dir):
                        for item in os.listdir(base_dir):
                            if "jdk" in item.lower():
                                java_exe = os.path.join(base_dir, item, "bin", "java.exe")
                                if os.path.exists(java_exe):
                                    java_candidates.append(java_exe)
            except Exception as java_search_err:
                print(f"[Allio] Aviso buscando Java: {java_search_err}")
            
            java_path = None
            print(f"[Allio] Buscando Java en {len(java_candidates)} ubicaciones...")
            for i, path in enumerate(java_candidates):
                print(f"[Allio] Verificando Java {i+1}: {path}")
                if os.path.exists(path):
                    java_path = path
                    print(f"[Allio] OK Java encontrado: {java_path}")
                    break
                else:
                    print(f"[Allio] No existe: {path}")
                    
            if not java_path:
                print("[Allio] ERROR: No se encontró Java 21+ en ninguna ubicación")
                QMessageBox.critical(self, "Error", "No se encontró Java 21+ instalado. Instálalo para continuar.")
                _reset_play_ui()
                return False
            
            # Verificar que la versión de Java sea compatible
            try:
                print(f"[Allio] Verificando versión de Java en: {java_path}")
                result = subprocess.run([java_path, '-version'], 
                                      capture_output=True, text=True, timeout=10)
                version_output = result.stderr + result.stdout
                print(f"[Allio] Salida de Java version: {version_output[:200]}")
                
                # Buscar versión en el output
                import re
                version_match = re.search(r'"(\d+)\.(\d+)', version_output)
                if not version_match:
                    version_match = re.search(r'version (\d+)', version_output)
                
                if version_match:
                    major_version = int(version_match.group(1))
                    print(f"[Allio] Versión de Java detectada: {major_version}")
                    
                    if major_version < 17:
                        print(f"[Allio] ERROR: Java {major_version} es muy antigua para Minecraft 1.21.10")
                        QMessageBox.critical(self, "Error Java", 
                            f"Java {major_version} es demasiado antigua.\n"
                            "Minecraft 1.21.10 requiere Java 17 o superior.\n"
                            "Recomendado: Java 21")
                        return False
                    elif major_version < 21:
                        print(f"[Allio] AVISO: Java {major_version} podría funcionar (recomendado: Java 21+)")
                    else:
                        print(f"[Allio] OK: Java {major_version} es compatible con Minecraft 1.21.10")
                else:
                    print("[Allio] AVISO: No se pudo determinar la versión de Java, continuando...")
                    
            except subprocess.TimeoutExpired:
                print("[Allio] ERROR: Timeout verificando versión de Java")
                _reset_play_ui()
                return False
            except Exception as java_ver_err:
                print(f"[Allio] ERROR verificando Java: {java_ver_err}")
                _reset_play_ui()
                return False
            # Obtener sesión autenticada desde Allio o desde el launcher oficial
            main_window: Optional[Any] = None
            candidate = None
            if hasattr(self, 'window'):
                try:
                    candidate = self.window()
                except Exception:
                    candidate = None
            if candidate is None and hasattr(self, 'parentWidget'):
                candidate = self.parentWidget()

            hops = 0
            while candidate is not None and hops < 10:
                if any(hasattr(candidate, attr) for attr in ('ensure_minecraft_session', 'get_auth_session')):
                    main_window = candidate
                    break
                candidate = candidate.parentWidget() if hasattr(candidate, 'parentWidget') else None
                hops += 1

            if main_window is None:
                app_cls = globals().get('QApplication')
                try:
                    app_inst = app_cls.instance() if app_cls is not None else None
                except Exception:
                    app_inst = None
                if app_inst is not None:
                    active = app_inst.activeWindow()
                    if active is not None and any(hasattr(active, attr) for attr in ('ensure_minecraft_session', 'get_auth_session')):
                        main_window = active

            if main_window is None:
                print("[Allio] Advertencia: no se encontró una ventana principal con sesión activa")

            session: dict[str, object] = {}
            if main_window is not None:
                if hasattr(main_window, 'ensure_minecraft_session'):
                    try:
                        session = main_window.ensure_minecraft_session()
                    except Exception as sess_err:
                        print(f"[Allio] Aviso ensure_minecraft_session: {sess_err}")
                if (not session or not isinstance(session, dict)) and hasattr(main_window, 'get_auth_session'):
                    try:
                        session = main_window.get_auth_session()
                    except Exception as sess_err:
                        print(f"[Allio] Aviso get_auth_session: {sess_err}")

            if not isinstance(session, dict):
                session = {}

            if not session.get('minecraft_token') or not session.get('minecraft_uuid'):
                official_session = load_official_launcher_session(minecraft_dir)
                if official_session:
                    if main_window is not None and hasattr(main_window, 'get_auth_session'):
                        try:
                            current = main_window.get_auth_session()
                        except Exception:
                            current = {}
                    else:
                        current = {}
                    merged = dict(current) if isinstance(current, dict) else {}
                    merged.update(official_session)
                    if main_window is not None and hasattr(main_window, 'update_auth_session'):
                        try:
                            main_window.update_auth_session(merged)
                        except Exception as upd_err:
                            print(f"[Allio] Aviso update_auth_session(importada): {upd_err}")
                    if main_window is not None and hasattr(main_window, 'save_config'):
                        try:
                            main_window.save_config()
                        except Exception as save_err:
                            print(f"[Allio] Aviso guardando sesión importada: {save_err}")

                    if main_window is not None and hasattr(main_window, 'get_auth_session'):
                        try:
                            session = main_window.get_auth_session()
                        except Exception:
                            session = merged
                    else:
                        session = merged
                else:
                    fallback_username = (
                        session.get('minecraft_username')
                        or session.get('profile_name')
                        or self.get_minecraft_java_username()
                        or getattr(main_window, '_username', None)
                    )
                    session = self._build_offline_session(fallback_username)
                    try:
                        QMessageBox.information(
                            self,
                            "Modo offline",
                            "No se encontró una sesión de Minecraft Java válida.\n"
                            "Se lanzará la instancia en modo offline usando el nombre seleccionado."
                        )
                    except Exception:
                        pass

            if not isinstance(session, dict):
                session = {}

            offline_mode = str(session.get('auth_source', '')).lower() == 'offline' or session.get('minecraft_token') == '0'

            if offline_mode:
                try:
                    offline_username = str(
                        session.get('minecraft_username')
                        or session.get('profile_name')
                        or getattr(self, '_username', None)
                    )
                    offline_username = _ensure_username(offline_username)
                    self._ensure_offline_skin_assets(minecraft_dir, offline_username)
                except Exception as offline_skin_err:
                    print(f"[Allio Avatar] Aviso preparando skin offline: {offline_skin_err}")

            token_expires = session.get('minecraft_token_expires_at')
            try:
                token_expires_val = float(token_expires)
            except Exception:
                token_expires_val = None
            if not offline_mode and token_expires_val and token_expires_val > 0 and token_expires_val <= time.time():
                try:
                    QMessageBox.warning(
                        self,
                        "Sesión expirada",
                        "El token de Minecraft obtenido del launcher oficial ha expirado.\n"
                        "Abre el launcher de Microsoft/Minecraft, inicia sesión y vuelve a intentarlo."
                    )
                except Exception:
                    pass
                _reset_play_ui()
                return False

            access_token = session.get('minecraft_token') or session.get('access_token')
            if not access_token or access_token == '0':
                if offline_mode:
                    access_token = '0'
                else:
                    try:
                        QMessageBox.warning(
                            self,
                            "Token no disponible",
                            "No se encontró el accessToken de Minecraft en la sesión actual.\n"
                            "Abre el launcher oficial para refrescar tu inicio de sesión y vuelve a intentarlo."
                        )
                    except Exception:
                        pass
                    _reset_play_ui()
                    return False

            uuid_value = session.get('minecraft_uuid') or session.get('minecraft_uuid_nodash')
            if isinstance(uuid_value, str) and len(uuid_value) == 32:
                uuid_formatted = f"{uuid_value[0:8]}-{uuid_value[8:12]}-{uuid_value[12:16]}-{uuid_value[16:20]}-{uuid_value[20:32]}"
                uuid_nodash = uuid_value
            elif isinstance(uuid_value, str) and len(uuid_value.replace('-', '')) == 32:
                uuid_nodash = uuid_value.replace('-', '')
                uuid_formatted = uuid_value
            elif offline_mode:
                offline_username = session.get('minecraft_username') or session.get('profile_name') or None
                offline_username = _ensure_username(offline_username)
                offline_uuid = uuid.uuid3(uuid.NAMESPACE_DNS, f"OfflinePlayer:{offline_username}")
                uuid_formatted = str(offline_uuid)
                uuid_nodash = offline_uuid.hex
                session['minecraft_uuid'] = uuid_formatted
                session['minecraft_uuid_nodash'] = uuid_nodash
            else:
                try:
                    QMessageBox.warning(
                        self,
                        "UUID no disponible",
                        "No se pudo determinar el UUID de Minecraft Java asociado a la sesión activa."
                    )
                except Exception:
                    pass
                _reset_play_ui()
                return False

            # Obtener username con prioridad correcta
            username = (
                session.get('minecraft_username')
                or session.get('profile_name')
                or session.get('gamertag')
                or session.get('ms_account_email')
                or None
            )
            username = _ensure_username(username)
            
            # Debug: mostrar qué valores tiene la sesión
            print(f"[Allio DEBUG] Datos de sesión para username:")
            print(f"  - minecraft_username: {session.get('minecraft_username')}")
            print(f"  - profile_name: {session.get('profile_name')}")
            print(f"  - gamertag: {session.get('gamertag')}")
            print(f"  - ms_account_email: {session.get('ms_account_email')}")
            print(f"  - username seleccionado: {username}")
            
            client_id = session.get('client_id') or session.get('client_token') or ''
            xuid = session.get('xuid') or session.get('xbox_userhash') or ''
            username = _ensure_username(username)
            client_id = str(client_id) if client_id is not None else ''
            xuid = str(xuid) if xuid is not None else ''
            if offline_mode and not client_id:
                client_id = session.get('client_token') or uuid.uuid4().hex
                session['client_token'] = client_id
            
            print(f"[Allio DEBUG] Username final que se usará: '{username}'")
                
            # Mostrar información sobre el modo de juego
            if offline_mode:
                print(f"[Allio] MODO OFFLINE como '{username}'")
                print(f"[Allio] INFO La cuenta Microsoft autenticada no tiene Minecraft Java Edition")
                print(f"[Allio] INFO Se puede jugar en servidores offline y LAN")
            else:
                print(f"[Allio] MODO ONLINE como '{username}'")
                print(f"[Allio] OK Cuenta autenticada con Minecraft Java Edition")
                
            # Construir el classpath (Fabric y librerías)
            import tempfile
            version_dir = os.path.join(minecraft_dir, "versions", fabric_version)
            libraries_dir = os.path.join(minecraft_dir, "libraries")
            fabric_jar = os.path.join(version_dir, f"{fabric_version}.jar")
            natives_ok, natives_list = ensure_lwjgl_natives(version_dir, libraries_dir)
            if not natives_ok:
                try:
                    QMessageBox.warning(self, "Faltan librerías nativas",
                        "No se pudieron preparar las librerías nativas de LWJGL necesarias para abrir la ventana del juego.\n"
                        "Se intentó extraerlas automáticamente desde los JARs 'natives-windows', pero el proceso falló.\n"
                        "Reinstala la versión 1.21.10 desde el launcher oficial o ejecuta 'python repair_and_install_assets.py'.")
                except Exception:
                    pass
                _reset_play_ui()
                return False
            else:
                print(f"[Allio] Natives preparados: {len(natives_list)} archivos")
            natives_dir = os.path.join(version_dir, "natives")
            # Recolectar y depurar jars para evitar duplicados de la misma librería con distinta versión
            lib_jars: list[str] = []
            for root, dirs, files in os.walk(libraries_dir):
                for file in files:
                    if file.endswith('.jar'):
                        lib_jars.append(os.path.join(root, file))

            artifact_map: dict[tuple[str, ...], dict[str, object]] = {}
            order_counter = 0
            for jar_path in sorted(lib_jars):
                rel = os.path.relpath(jar_path, libraries_dir)
                parts = rel.split(os.sep)
                if len(parts) < 3:
                    continue
                version_segment = parts[-2]
                coord_key = tuple(parts[:-2])
                ver_key = _version_sort_key(version_segment)
                entry = artifact_map.get(coord_key)
                if entry is None:
                    artifact_map[coord_key] = {
                        'version_key': ver_key,
                        'path': jar_path,
                        'order': order_counter,
                    }
                    order_counter += 1
                else:
                    if ver_key >= entry['version_key']:
                        entry['version_key'] = ver_key
                        entry['path'] = jar_path

            jars = [fabric_jar]
            client_jar = os.path.join(minecraft_dir, 'versions', mc_base_version, f"{mc_base_version}.jar")
            if os.path.exists(client_jar):
                jars.append(client_jar)
            jars.extend(entry['path'] for entry in sorted(artifact_map.values(), key=lambda e: e['order']))

            with tempfile.NamedTemporaryFile('w', delete=False, suffix='.txt') as cpfile:
                cpfile.write(";".join(jars))
                classpath_file = cpfile.name

            asset_index = None
            indexes_dir = os.path.join(minecraft_dir, 'assets', 'indexes')
            if os.path.exists(indexes_dir):
                try:
                    candidates = [f for f in os.listdir(indexes_dir) if f.endswith('.json')]
                    preferred_prefix = mc_base_version.split('.')[:2]
                    preferred = f"{'.'.join(preferred_prefix)}.json" if preferred_prefix else None
                    for candidate in sorted(candidates):
                        if candidate.startswith(mc_base_version) and candidate.endswith('.json'):
                            asset_index = candidate[:-5]
                            break
                    if not asset_index and preferred and preferred in candidates:
                        asset_index = preferred[:-5]
                    if not asset_index and candidates:
                        asset_index = candidates[0][:-5]
                except Exception:
                    asset_index = None
            if not asset_index:
                asset_index = mc_base_version if mc_base_version else '1.21'

            args = [
                java_path,
                f'-Djava.library.path={natives_dir}',
                f'-Dorg.lwjgl.librarypath={natives_dir}',
                f'-Dorg.lwjgl.openal.LibraryPath={natives_dir}',
                '-Duser.language=es',
                '-Duser.country=ES',
                '-cp', f'@{classpath_file}',
                'net.fabricmc.loader.impl.launch.knot.KnotClient',
                '--username', username,
                '--version', fabric_version,
                '--gameDir', instance_path,
                '--assetsDir', os.path.join(minecraft_dir, 'assets'),
                '--assetIndex', asset_index,
                '--uuid', uuid_formatted,
                '--accessToken', access_token,
                '--clientId', client_id,
                '--xuid', xuid,
                '--userType', 'msa',
                '--userProperties', '{}',
                '--versionType', 'release'
            ]
            # Validar que todos los elementos son strings
            print(f"[Allio] Validando argumentos de lanzamiento...")
            for i, arg in enumerate(args):
                if not isinstance(arg, str):
                    raise ValueError(f"args[{i}] no es string: {type(arg)} = {arg}")
            
            print(f"[Allio] Argumentos validados correctamente ({len(args)} argumentos)")
            print(f"[Allio] Java path: {java_path}")
            print(f"[Allio] Instance path: {instance_path}")
            print(f"[Allio] Username: {username}")
            print(f"[Allio] UUID: {uuid_formatted}")
            print(f"[Allio] Lanzando Minecraft directo con classpath en archivo: {classpath_file}")
            try:
                if self.play_tile:
                    self.play_tile.set_downloading("Launching Minecraft", 85)
            except Exception:
                pass

            def _write_launch_log(log_text: str) -> Optional[str]:
                """Guarda el log de lanzamiento en la carpeta de la instancia para fácil diagnóstico."""
                try:
                    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                    log_path = os.path.join(instance_path, f"allio_launch_{timestamp}.log")
                    with open(log_path, "w", encoding="utf-8") as log_file:
                        log_file.write(log_text)
                    print(f"[Allio] Log de lanzamiento guardado en: {log_path}")
                    return log_path
                except Exception as log_err:
                    print(f"[Allio] Aviso guardando log de lanzamiento: {log_err}")
                    return None

            try:
                if not os.path.exists(instance_path):
                    raise FileNotFoundError(f"El directorio de instancia no existe: {instance_path}")

                if not os.path.exists(java_path):
                    raise FileNotFoundError(f"Java no encontrado en: {java_path}")

                print("[Allio] Ejecutando proceso Minecraft...")
                process = subprocess.Popen(
                    args,
                    cwd=instance_path,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                print(f"[Allio] Proceso iniciado con PID: {process.pid}")

                try:
                    process.wait(timeout=6)
                    # Si `wait` no lanza excepción es porque terminó antes del timeout
                    stdout_bytes, stderr_bytes = process.communicate(timeout=2)
                    stdout_text = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
                    stderr_text = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""
                    exit_code = process.returncode
                    print(f"[Allio] ERROR: Minecraft terminó de inmediato (salida {exit_code})")
                    if stdout_text:
                        print(f"[Allio] STDOUT (primeros 400 chars): {stdout_text[:400]}")
                    if stderr_text:
                        print(f"[Allio] STDERR (primeros 400 chars): {stderr_text[:400]}")
                    
                    # Detectar error específico de ASM duplicado
                    error_lower = (stdout_text + stderr_text).lower()
                    is_asm_error = "duplicate" in error_lower and "asm" in error_lower and "classes" in error_lower

                    combined_log = (
                        "============= ALLIO LAUNCHER =============\n"
                        f"Fecha: {datetime.now().isoformat()}\n"
                        f"Java path: {java_path}\n"
                        f"Instancia: {instance_path}\n"
                        f"Exit code: {exit_code}\n"
                        "-------------- STDOUT --------------\n"
                        f"{stdout_text}\n"
                        "-------------- STDERR --------------\n"
                        f"{stderr_text}\n"
                    )
                    log_path = _write_launch_log(combined_log)

                    # Crear mensaje de error personalizado según el tipo de problema
                    if is_asm_error:
                        details = (
                            "ERROR: Librerías duplicadas detectadas (duplicate ASM classes).\n\n"
                            "Este error se produce cuando hay versiones antiguas de librerías en el classpath.\n\n"
                            "SOLUCIÓN:\n"
                            "1. Cierra completamente Allio Client\n"
                            "2. Abre el launcher oficial de Minecraft\n"
                            "3. Ejecuta la versión 1.21.10 una vez\n"
                            "4. Vuelve a abrir Allio Client\n\n"
                            "El launcher automáticamente limpiará las librerías duplicadas al siguiente inicio."
                        )
                        if log_path:
                            details += f"\n\nLog completo guardado en:\n{log_path}"
                    else:
                        details = f"El proceso de Minecraft terminó inmediatamente (código {exit_code})."
                        if log_path:
                            details += f"\nSe guardó un log aqui:\n{log_path}"
                        if stderr_text:
                            snippet = stderr_text.strip().splitlines()
                            if snippet:
                                details += f"\n\nUltimo mensaje:\n{snippet[-1][:240]}"

                    QMessageBox.critical(
                        self,
                        "Error lanzando Minecraft" if not is_asm_error else "Librerías duplicadas",
                        details,
                    )
                    _reset_play_ui()
                    return False
                except subprocess.TimeoutExpired:
                    # Proceso sigue vivo: considerarlo éxito y cerrar pipes para evitar bloqueos
                    print("[Allio] Minecraft lanzado correctamente - proceso sigue ejecutándose")
                    if process.stdout:
                        process.stdout.close()
                    if process.stderr:
                        process.stderr.close()
                    try:
                        if self.play_tile:
                            self.play_tile.set_playing()
                    except Exception:
                        pass
                    self.minecraft_process = process
                    
                    # Monitorear el proceso en segundo plano para restaurar el botón cuando termine
                    def _monitor_minecraft():
                        try:
                            process.wait()
                            print("[Allio] Minecraft ha cerrado, restaurando botón Jugar")
                            # clear launching flag
                            try:
                                self._is_launching = False
                            except Exception:
                                pass
                            if hasattr(self, 'play_tile') and self.play_tile:
                                self.play_tile.set_idle()
                            if hasattr(self, 'play_btn') and self.play_btn:
                                self.play_btn.show()
                        except Exception as monitor_err:
                            print(f"[Allio] Error monitoreando Minecraft: {monitor_err}")
                    
                    import threading
                    try:
                        self._is_launching = True
                    except Exception:
                        pass
                    monitor_thread = threading.Thread(target=_monitor_minecraft, daemon=True)
                    monitor_thread.start()
                    
                    return True

            except FileNotFoundError as fnf_e:
                print(f"[Allio] ERROR: Archivo no encontrado: {fnf_e}")
                QMessageBox.critical(self, "Error", f"Archivo no encontrado: {fnf_e}")
                _reset_play_ui()
                return False
            except Exception as popen_e:
                print(f"[Allio] ERROR ejecutando subprocess: {popen_e}")
                import traceback
                traceback.print_exc()
                QMessageBox.critical(self, "Error", f"Error ejecutando Minecraft: {popen_e}")
                try:
                    if self.play_tile:
                        self.play_tile.set_idle()
                        if hasattr(self, 'play_btn'):
                            self.play_btn.show()
                except Exception:
                    pass
                return False
        except Exception as e:
            print(f"[Allio] ERROR al lanzar Minecraft: {str(e)}")
            import traceback
            traceback.print_exc()
            QMessageBox.critical(self, "Error", f"Error al lanzar Minecraft: {str(e)}")
            try:
                if self.play_tile:
                    self.play_tile.set_idle()
                    if hasattr(self, 'play_btn'):
                        self.play_btn.show()
            except Exception:
                pass
            return False
            
            # Verificar Fabric Loader
            minecraft_dir = os.path.join(os.getenv('APPDATA'), '.minecraft')
            fabric_version = "fabric-loader-0.17.3-1.21.10"
            fabric_path = os.path.join(minecraft_dir, "versions", fabric_version, f"{fabric_version}.json")
            
            if not os.path.exists(fabric_path):
                QMessageBox.warning(self, "Fabric no encontrado", 
                    f"Fabric Loader {fabric_version} no está instalado.\n\n"
                    f"Por favor instálalo desde:\n"
                    f"https://fabricmc.net/use/installer/\n\n"
                    f"Selecciona Minecraft 1.21.10 y Loader 0.17.3")
                return False

            # Obtener sesión de Microsoft
            session = self.microsoft_login()
            if not session:
                QMessageBox.critical(self, "Error", "No se pudo iniciar sesión con Microsoft")
                return False
                
            # Preparar argumentos de lanzamiento
            minecraft_launcher_options = {
                "username": session['username'],
                "uuid": session['uuid'],
                "token": session['access_token'],
            }

            print(f"[Allio] INICIO Iniciando Minecraft como {username}")
            
            try:
                minecraft_command = None
                if minecraft_launcher_lib is not None:
                    # Usar minecraft-launcher-lib si está disponible
                    try:
                        minecraft_command = minecraft_launcher_lib.command.get_minecraft_command(
                            fabric_version,
                            minecraft_dir,
                            minecraft_launcher_options
                        )
                        print(f"[Allio] Comando de Minecraft generado exitosamente")
                    except Exception as launcher_err:
                        print(f"[Allio] Aviso: error al generar comando con minecraft_launcher_lib ({launcher_err}), usando fallback manual")
                        minecraft_command = None
                
                if minecraft_command is None:
                    # Lanzamiento manual como fallback
                    java_path = os.path.join(os.getenv('ProgramFiles', ''), 'Java', 'jdk-21', 'bin', 'java.exe')
                    # En Windows, usar semicolon como separador en el classpath
                    libraries_path = os.path.join(minecraft_dir, 'libraries', '*')
                    minecraft_command = [
                        java_path,
                        f"-Djava.library.path={os.path.join(minecraft_dir, 'versions', fabric_version, 'natives')}",
                        "-cp", libraries_path,
                        "net.fabricmc.loader.impl.launch.knot.KnotClient",
                        "--username", session['username'],
                        "--version", fabric_version,
                        "--gameDir", instance_path,
                        "--assetsDir", os.path.join(minecraft_dir, 'assets'),
                        "--assetIndex", "1.21",
                        "--uuid", session['uuid'],
                        "--accessToken", session['access_token'],
                        "--clientId", "",
                        "--xuid", "",
                        "--userType", "msa",
                        "--versionType", "release"
                    ]
                
                # Validar que minecraft_command es una lista
                if not isinstance(minecraft_command, list):
                    raise ValueError(f"minecraft_command debe ser una lista, pero es {type(minecraft_command)}")
                
                # Lanzar Minecraft sin mostrar consola
                subprocess.Popen(minecraft_command, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                print("[Allio] OK Minecraft lanzado exitosamente")
                return True

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error al lanzar Minecraft: {str(e)}")
                print(f"[Allio] ERROR al lanzar Minecraft: {str(e)}")
                return False
            if main_window is not None:
                try:
                    if hasattr(main_window, 'ensure_minecraft_session'):
                        session = main_window.ensure_minecraft_session()
                    elif hasattr(main_window, 'get_auth_session'):
                        session = main_window.get_auth_session()
                except Exception as sess_err:
                    print(f"[Allio] Aviso obteniendo sesión: {sess_err}")
                    session = {}

            try:
                print(f"[Allio Auth] Sesión previa al lanzamiento: claves={sorted(session.keys()) if isinstance(session, dict) else 'N/A'}")
            except Exception:
                pass

            # Determinar usuario y tokens actuales (sin valores por defecto hardcodeados)
            username = session.get('minecraft_username') or session.get('profile_name') or session.get('gamertag') or self.get_minecraft_java_username() or getattr(main_window, '_username', None)
            access_token = session.get('minecraft_token')
            minecraft_uuid = session.get('minecraft_uuid') or session.get('minecraft_uuid_nodash')
            xuid = session.get('xuid', '')
            account_email = session.get('ms_account_email', '')

            # Asegurar que el username nunca sea la cadena "Player" y esté saneado
            username = _ensure_username(username)

            if (not access_token or not minecraft_uuid) and main_window is not None and hasattr(main_window, 'ensure_minecraft_session'):
                try:
                    session = main_window.ensure_minecraft_session(force_refresh=True)
                    access_token = session.get('minecraft_token')
                    minecraft_uuid = session.get('minecraft_uuid') or session.get('minecraft_uuid_nodash')
                    username = session.get('minecraft_username') or username
                    print(f"[Allio Auth] Sesión tras force_refresh: claves={sorted(session.keys())}")
                except Exception as sess_err:
                    print(f"[Allio] Error refrescando sesión: {sess_err}")

            if not access_token or not minecraft_uuid:
                try:
                    print(f"[Allio Auth] Falta token/uuid. access_token={'sí' if access_token else 'no'}, uuid={'sí' if minecraft_uuid else 'no'}")
                except Exception:
                    pass
                QMessageBox.warning(self, "Inicia sesión primero", 
                    "Necesitas iniciar sesión con tu cuenta de Microsoft (Minecraft Java) antes de lanzar la instancia Hardcore.")
                return False

            uuid_no_dash = minecraft_uuid.replace('-', '')
            if len(uuid_no_dash) == 32:
                uuid_formatted = f"{uuid_no_dash[0:8]}-{uuid_no_dash[8:12]}-{uuid_no_dash[12:16]}-{uuid_no_dash[16:20]}-{uuid_no_dash[20:32]}"
            else:
                QMessageBox.warning(self, "UUID inválido", 
                    "No se pudo determinar el UUID de Minecraft Java para esta cuenta.\n"
                    "Inicia sesión de nuevo o comprueba que la cuenta posee Minecraft Java.")
                return False

            # Preparar client token persistente
            client_token = session.get('client_token') or getattr(main_window, '_client_token', '') or uuid.uuid4().hex
            if main_window is not None:
                try:
                    if hasattr(main_window, '_client_token'):
                        if not main_window._client_token:
                            main_window._client_token = client_token
                    if not offline_mode and hasattr(main_window, 'update_auth_session'):
                        merged_session = dict(session)
                        merged_session['client_token'] = client_token
                        merged_session['minecraft_uuid'] = uuid_formatted
                        merged_session['minecraft_uuid_nodash'] = uuid_no_dash
                        merged_session['minecraft_token'] = access_token
                        merged_session['minecraft_username'] = username
                        main_window.update_auth_session(merged_session)
                    if hasattr(main_window, 'save_config'):
                        try:
                            main_window.save_config()
                        except Exception as cfg_err:
                            print(f"[Allio] Aviso guardando configuración: {cfg_err}")
                except Exception as e:
                    print(f"[Allio] Advertencia al actualizar client_token: {e}")
            
            print(f"[Allio]  Configurando Hardcore para {username}...")

            # Intentar copiar el avatar caché local a .minecraft/assets/skins/<username>.png
            # Esto ayuda cuando lanzamos en modo offline para que clientes/mods que respeten skins locales
            try:
                appdata = os.getenv('APPDATA', '') or ''
                avatars_dir = os.path.join(appdata, 'AllioClient', 'avatars')
                avatar_src = os.path.join(avatars_dir, f"{str(username).casefold()}.png")
                skins_dir = os.path.join(minecraft_dir, 'assets', 'skins')
                os.makedirs(skins_dir, exist_ok=True)
                if os.path.exists(avatar_src):
                    dst = os.path.join(skins_dir, f"{username}.png")
                    try:
                        shutil.copy2(avatar_src, dst)
                        print(f"[Allio Avatar] Copiado avatar local a skins: {dst}")
                    except Exception as cp_e:
                        print(f"[Allio Avatar] Error copiando avatar a skins: {cp_e}")
                else:
                    # Como fallback intentar usar avatar en caché por nombre en memoria
                    # self._profile_image puede contener QPixmap; guardarla si es posible
                    try:
                        if getattr(self, '_profile_image', None) is not None:
                            try:
                                from PyQt6.QtCore import QBuffer, QIODevice
                                buf = QBuffer()
                                buf.open(QIODevice.WriteOnly)
                                self._profile_image.save(buf, 'PNG')
                                buf.seek(0)
                                with open(os.path.join(skins_dir, f"{username}.png"), 'wb') as f_out:
                                    f_out.write(buf.data())
                                print(f"[Allio Avatar] Guardado _profile_image a skins para {username}")
                            except Exception:
                                pass
                    except Exception:
                        pass
            except Exception as e:
                print(f"[Allio Avatar] Error preparando skin local: {e}")

            if minecraft_launcher_lib is not None:
                try:
                    lib_options = {
                        "username": username,
                        "uuid": uuid_no_dash,
                        "token": access_token,
                    }

                    try:
                        lib_options["accountType"] = "msa"
                    except Exception:
                        pass

                    try:
                        command = minecraft_launcher_lib.command.get_minecraft_command(
                            fabric_version,
                            minecraft_dir,
                            lib_options,
                        )
                        
                        if not isinstance(command, list):
                            raise ValueError(f"command debe ser una lista, pero es {type(command)}")
                        
                        print(f"[Allio] Lanzando instancia Hardcore mediante minecraft_launcher_lib...")
                        subprocess.Popen(command, cwd=minecraft_dir, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                        QMessageBox.information(
                            self,
                            "Minecraft lanzandose",
                            "La instancia Hardcore se esta abriendo directamente con tus credenciales de Microsoft."
                        )
                        return True
                    except Exception as perm_err:
                        print(f"[Allio] Aviso: error en Hardcore con minecraft_launcher_lib ({perm_err})")
                        raise  # Re-lanzar para que lo maneje el except externo
                except Exception as direct_err:
                    print(f"[Allio] Aviso: ejecución directa con minecraft_launcher_lib falló ({direct_err})")
            else:
                print("[Allio] minecraft_launcher_lib no está disponible; usando launcher oficial como respaldo.")
            
            # Crear perfil del launcher
            try:
                launcher_profiles_path = os.path.join(minecraft_dir, 'launcher_profiles.json')
                
                # Perfil Hardcore
                hardcore_profile = {
                    "name": "Allio Hardcore",
                    "type": "custom",
                    "gameDir": instance_path,
                    "lastVersionId": fabric_version,
                    "javaArgs": "-Xmx4G -Xms2G",
                    "resolution": {"width": 1920, "height": 1080},
                    "icon": "Crafting_Table"
                }
                
                # Leer perfiles existentes
                profiles_data: dict = {"profiles": {}, "settings": {}, "version": 3}
                if os.path.exists(launcher_profiles_path):
                    try:
                        with open(launcher_profiles_path, 'r', encoding='utf-8') as f:
                            profiles_data = json.load(f)
                    except Exception as e:
                        print(f"[Allio] Aviso: no se pudo leer launcher_profiles.json ({e})")
                if not isinstance(profiles_data, dict):
                    profiles_data = {"profiles": {}, "settings": {}, "version": 3}

                profiles_data.setdefault('profiles', {})
                profiles_data.setdefault('settings', {})
                profiles_data.setdefault('authenticationDatabase', {})
                
                # Agregar nuestro perfil
                now_iso = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
                hardcore_profile.setdefault("created", now_iso)
                hardcore_profile["lastUsed"] = now_iso
                hardcore_profile["associatedAccount"] = uuid_no_dash
                hardcore_profile["playerUUID"] = uuid_no_dash
                profiles_data['profiles']['allio_hardcore'] = hardcore_profile
                profiles_data['settings'] = {
                    "enableAdvanced": True,
                    "enableAnalytics": False,
                    "keepLauncherOpen": False,
                    "showGameLog": True
                }

                # Actualizar base de autenticación con los tokens activos
                auth_entry = {
                    "accessToken": access_token,
                    "username": account_email or username,
                    "uuid": uuid_no_dash,
                    "name": username,
                    "xuid": xuid,
                    "type": "msa",
                    "userType": "msa",
                    "userProperties": {},
                    "clientToken": client_token
                }
                profiles_data['authenticationDatabase'][uuid_no_dash] = auth_entry

                profiles_data['selectedUser'] = {
                    "account": uuid_no_dash,
                    "profile": uuid_no_dash
                }
                profiles_data['clientToken'] = client_token
                profiles_data['selectedProfile'] = 'allio_permadeath'
                
                # Guardar launcher_profiles.json
                os.makedirs(os.path.dirname(launcher_profiles_path), exist_ok=True)
                with open(launcher_profiles_path, 'w', encoding='utf-8') as f:
                    json.dump(profiles_data, f, indent=2, ensure_ascii=False)
                
                print("[Allio] OK Perfil 'Allio PermadeatH' creado")
                
                # NUEVO: Crear/actualizar launcher_accounts.json para que el launcher oficial reconozca la cuenta
                try:
                    launcher_accounts_path = os.path.join(minecraft_dir, 'launcher_accounts.json')
                    accounts_data: dict = {"accounts": {}, "formatVersion": 3}
                    
                    # Leer archivo existente si existe
                    if os.path.exists(launcher_accounts_path):
                        try:
                            with open(launcher_accounts_path, 'r', encoding='utf-8') as f:
                                accounts_data = json.load(f)
                        except Exception as e:
                            print(f"[Allio] Aviso: no se pudo leer launcher_accounts.json ({e})")
                    
                    if not isinstance(accounts_data, dict):
                        accounts_data = {"accounts": {}, "formatVersion": 3}
                    
                    accounts_data.setdefault('accounts', {})
                    accounts_data.setdefault('formatVersion', 3)
                    
                    # Crear entrada de cuenta de Microsoft
                    account_id = uuid_no_dash
                    account_entry = {
                        "accessToken": access_token,
                        "accessTokenExpiresAt": datetime.utcnow().isoformat() + "Z",
                        "eligibleForMigration": False,
                        "hasMultipleProfiles": False,
                        "legacy": False,
                        "localId": account_id,
                        "minecraftProfile": {
                            "id": uuid_formatted,
                            "name": username
                        },
                        "persistent": True,
                        "remoteId": account_id,
                        "type": "msa",
                        "username": account_email or username,
                        "userProperites": []
                    }
                    
                    # Si tenemos más información de Microsoft, agregarla
                    if xuid:
                        account_entry["xuid"] = xuid
                    if session.get('ms_refresh_token'):
                        account_entry["refreshToken"] = session.get('ms_refresh_token')
                    if client_token:
                        account_entry["clientToken"] = client_token
                    
                    # Agregar la cuenta
                    accounts_data['accounts'][account_id] = account_entry
                    
                    # Establecer como cuenta activa
                    accounts_data['activeAccountLocalId'] = account_id
                    accounts_data['activeUser'] = account_id
                    
                    # Guardar launcher_accounts.json
                    with open(launcher_accounts_path, 'w', encoding='utf-8') as f:
                        json.dump(accounts_data, f, indent=2, ensure_ascii=False)
                    
                    print(f"[Allio] OK Cuenta de Microsoft guardada en launcher_accounts.json: {username}")
                    
                except Exception as acc_err:
                    print(f"[Allio] AVISO Error guardando launcher_accounts.json: {acc_err}")
                    # No es crítico, continuar
                
            except Exception as e:
                print(f"[Allio] AVISO Error creando perfil: {e}")
            
            # Buscar y abrir launcher oficial
            launcher_paths = [
                r"C:\Program Files (x86)\Minecraft Launcher\MinecraftLauncher.exe",
                r"C:\Program Files\Minecraft Launcher\MinecraftLauncher.exe",
                os.path.join(os.getenv('LOCALAPPDATA'), 'Programs', 'Minecraft Launcher', 'MinecraftLauncher.exe')
            ]
            
            launcher_path = None
            for path in launcher_paths:
                if os.path.exists(path):
                    launcher_path = path
                    break
            
            if not launcher_path:
                QMessageBox.critical(self, "Launcher no encontrado", 
                    "No se encontró el launcher oficial de Minecraft.\n"
                    "Por favor instálalo desde minecraft.net")
                return False
            
            try:
                print(f"[Allio]  Abriendo Minecraft Launcher...")
                # Abrir launcher oficial sin mostrar consola extra
                process = subprocess.Popen([launcher_path, "--workingDirectory", minecraft_dir], 
                                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                print(f"[Allio] OK ¡Launcher oficial abierto! (PID: {process.pid})")
                # Mostrar instrucciones detalladas
                QMessageBox.information(self, "¡Launcher Abierto!", 
                    f"OK ¡Minecraft Launcher abierto correctamente!\n\n"
                    f"📋 INSTRUCCIONES PARA JUGAR:\n"
                    f"1. Busca el perfil: 'Allio PermadeatH'\n"
                    f"2. Selecciónalo en la lista desplegable\n"
                    f"3. Haz clic en JUGAR\n"
                    f"4. ¡Disfruta tus {len(mod_files)} mods!\n\n"
                    f"👤 Usuario: {username}\n"
                    f"📁 Instancia: PermadeatH\n"
                    f" Versión: {fabric_version}")
                
                return True
                
            except Exception as e:
                print(f"[Allio] ERROR Error abriendo launcher: {e}")
                QMessageBox.critical(self, "Error", f"Error al abrir launcher: {e}")
                return False
            
        except Exception as e:
            print(f"[Allio] ERROR Error general: {e}")
            QMessageBox.critical(self, "Error", f"Error: {e}")
            return False 

    def launch_fabric_instance(self, instance_path):
        """Lanza directamente la instancia específica de Minecraft con Fabric"""
        try:
            print(f"[Allio] Preparando lanzamiento DIRECTO de instancia Fabric: {instance_path}")
            
            # Verificar que Java esté disponible
            java_executable = self.find_java_executable()
            if not java_executable:
                QMessageBox.warning(self, "Java no encontrado", 
                    "No se pudo encontrar una instalación de Java.\n\n"
                    "Por favor instala Java 21 o superior desde:\n"
                    "https://adoptium.net/")
                return False
            
            # Verificar que existe la carpeta de mods
            mods_path = os.path.join(instance_path, 'mods')
            if not os.path.exists(mods_path):
                print("[Allio] No se encontró carpeta de mods")
                QMessageBox.warning(self, "Instancia inválida", 
                    "No se encontró la carpeta de mods en la instancia PermadeatH")
                return False
            
            # Obtener el username de Minecraft Java desde la configuración
            username = self.get_minecraft_java_username()
            if not username:
                QMessageBox.warning(self, "Usuario no encontrado", 
                    "No se pudo obtener el nombre de usuario de Minecraft Java.\n"
                    "Por favor inicia sesión primero.")
                return False
            
            # LANZAMIENTO DIRECTO (prioridad principal)
            print("[Allio] OK Usando método de lanzamiento DIRECTO")
            return self.launch_fabric_direct_improved(java_executable, instance_path, username)
                
        except Exception as e:
            print(f"[Allio] Error lanzando instancia Fabric: {e}")
            QMessageBox.warning(self, "Error de lanzamiento", 
                f"Error al lanzar la instancia de Fabric:\n{e}")
            return False

    def launch_via_launcher_profiles(self, instance_path, username):
        """Intenta lanzar usando el sistema de perfiles del launcher oficial"""
        try:
            launcher_profiles_path = os.path.join(os.getenv('APPDATA', ''), '.minecraft', 'launcher_profiles.json')
            
            # Crear perfil temporal para la instancia
            profile_data = {
                "profiles": {
                    "AllioClient_PermadeatH": {
                        "name": "AllioClient PermadeatH",
                        "type": "custom",
                        "gameDir": instance_path,
                        "lastVersionId": "fabric-loader-0.17.3-1.21.10",
                        "javaArgs": "-Xmx4G -Xms1G",
                        "resolution": {
                            "width": 1920,
                            "height": 1080
                        },
                        "created": "2025-10-26T17:00:00.000Z",
                        "lastUsed": "2025-10-26T17:00:00.000Z"
                    }
                },
                "settings": {
                    "enableAdvanced": True,
                    "enableAnalytics": False,
                    "enableSnapshots": False,
                    "keepLauncherOpen": False,
                    "showGameLog": False,
                    "showMenu": False,
                    "soundOn": False
                },
                "version": 3
            }
            
            # Si ya existe el archivo, combinarlo
            if os.path.exists(launcher_profiles_path):
                try:
                    with open(launcher_profiles_path, 'r', encoding='utf-8') as f:
                        existing_data = json.load(f)
                        if 'profiles' in existing_data:
                            existing_data['profiles']['AllioClient_PermadeatH'] = profile_data['profiles']['AllioClient_PermadeatH']
                            profile_data = existing_data
                except Exception as e:
                    print(f"[Allio] Error leyendo launcher_profiles existente: {e}")
            
            # Guardar el perfil
            os.makedirs(os.path.dirname(launcher_profiles_path), exist_ok=True)
            with open(launcher_profiles_path, 'w', encoding='utf-8') as f:
                json.dump(profile_data, f, indent=2)
            
            print("[Allio] Perfil de launcher creado, lanzando Minecraft...")
            
            # Lanzar Minecraft con el perfil específico
            launcher_path = self.find_minecraft_launcher()
            if launcher_path:
                # Lanzar con argumentos para usar el perfil específico sin mostrar consola extra
                cmd = [launcher_path, '--workDir', os.getenv('APPDATA', '') + '\\.minecraft']
                subprocess.Popen(cmd, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                
                QMessageBox.information(self, "Minecraft Lanzado", 
                    f"¡Minecraft se ha abierto!\n\n"
                    f"Para usar tu instancia PermadeatH:\n"
                    f"1. Selecciona el perfil 'AllioClient PermadeatH'\n"
                    f"2. Haz clic en JUGAR\n\n"
                    f"Usuario: {username}")
                return True
            
            return False
            
        except Exception as e:
            print(f"[Allio] Error con método de launcher profiles: {e}")
            return False

    def launch_fabric_direct_improved(self, java_executable, instance_path, username):
        """Método directo para lanzar DIRECTAMENTE la instancia personalizada de Minecraft"""
        try:
            print("[Allio] OK Lanzando DIRECTAMENTE tu instancia PermadeatH...")
            # Validar librerías JAR corruptas antes de lanzar
            try:
                mc_dir = os.path.join(os.getenv('APPDATA', ''), '.minecraft')
                moved = validate_and_cleanup_corrupt_jars(mc_dir)
                if moved:
                    print(f"[Allio] Aviso: se han movido {len(moved)} jars corruptos a '.minecraft/corrupt_libraries'")
            except Exception as e:
                print(f"[Allio] Error validando jars antes de launch_direct: {e}")
            
            # UUID del usuario
            uuid = "2e82d582-c5dd-44a0-887e-e13661fc2866"
            
            # Crear script de lanzamiento robusto
            script_path = self.create_direct_minecraft_script(java_executable, instance_path, username, uuid)
            
            if not script_path:
                print("[Allio] ERROR Error creando script de lanzamiento")
                return False
            
            print(f"[Allio] OK Ejecutando tu instancia directamente...")
            
            # Ejecutar el script PowerShell con la política de ejecución correcta
            process = subprocess.Popen(
                ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", script_path],
                cwd=instance_path,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            
            print(f"[Allio] OK ¡Minecraft PermadeatH lanzado directamente! (PID: {process.pid})")
            return True
            
        except Exception as e:
            print(f"[Allio] ERROR Error: {e}")
            return False

    def create_direct_minecraft_script(self, java_exe, instance_path, username, uuid):
        """Crea script que usa el launcher oficial para abrir Fabric con directorio personalizado"""
        try:
            import tempfile
            import os
            
            # Verificar que Java 21+ esté disponible
            java_21_path = self.find_java21_executable()
            if not java_21_path:
                print("[Allio] ERROR ERROR CRÍTICO: Se requiere Java 21+ para Minecraft 1.21.10")
                return None
            
            # Crear script PowerShell que abre el launcher oficial con configuración
            script_fd, script_path = tempfile.mkstemp(suffix='.ps1', dir=instance_path, text=True)
            
            script_content = f'''# PermadeatH Instance - Launcher Oficial
Write-Host "========================================"
Write-Host "     ALLIO CLIENT - PERMADEATH"
Write-Host "========================================"
Write-Host "Usuario: {username}"
Write-Host "Java: {java_21_path}"
Write-Host "Directorio: {instance_path.replace(chr(92), chr(92)+chr(92))}"
Write-Host "========================================"

$minecraftDir = "$env:APPDATA\\.minecraft"
$fabricVersion = "fabric-loader-0.17.3-1.21.10"

Write-Host "Verificando Fabric Loader..."
$fabricDir = "$minecraftDir\\versions\\$fabricVersion"
if (-not (Test-Path "$fabricDir\\$fabricVersion.json")) {{
    Write-Host "ERROR: Fabric Loader $fabricVersion no encontrado" -ForegroundColor Red
    Write-Host "Instala Fabric desde fabricmc.net"
    Read-Host "Presiona Enter para salir"
    exit 1
}}

Write-Host "Buscando launcher oficial..."
$launcherPaths = @(
    "C:\\Program Files (x86)\\Minecraft Launcher\\MinecraftLauncher.exe",
    "C:\\Program Files\\Minecraft Launcher\\MinecraftLauncher.exe",
    "$env:LOCALAPPDATA\\Programs\\Minecraft Launcher\\MinecraftLauncher.exe"
)

$launcherPath = $null
foreach ($path in $launcherPaths) {{
    if (Test-Path $path) {{
        $launcherPath = $path
        break
    }}
}}

if (-not $launcherPath) {{
    Write-Host "ERROR: Launcher oficial no encontrado" -ForegroundColor Red
    Read-Host "Presiona Enter para salir"
    exit 1
}}

Write-Host "Abriendo launcher oficial..." -ForegroundColor Green
Write-Host ""
Write-Host "INSTRUCCIONES IMPORTANTES:" -ForegroundColor Yellow
Write-Host "1. Selecciona fabric-loader-0.17.3-1.21.10"
Write-Host "2. Edita el perfil (icono de engranaje)"
Write-Host "3. Cambia 'Directorio del juego' a:"
Write-Host "   {instance_path.replace(chr(92), chr(92)+chr(92))}"
Write-Host "4. Guarda y presiona JUGAR"
Write-Host "5. Disfruta tus mods PermadeatH!"
Write-Host ""

Start-Process $launcherPath -ArgumentList "--workingDirectory", $minecraftDir

Write-Host "Launcher abierto. Configura segun las instrucciones."
Start-Sleep 3
'''

            with os.fdopen(script_fd, 'w', encoding='utf-8') as f:
                f.write(script_content)
            
            print(f"[Allio] OK Script guardado en: {script_path}")
            
            return script_path
            
        except Exception as e:
            print(f"[Allio] ERROR Error creando script: {e}")
            import traceback
            traceback.print_exc()
            return None

    def find_java21_executable(self):
        """Busca Java 21 o superior en el sistema"""
        import glob
        
        # Buscar todas las versiones de Java (incluyendo 21, 22, 23, 24, 25, etc.)
        java_paths = [
            r"C:\Program Files\Java\jdk-*\bin\java.exe",
            r"C:\Program Files\Java\jre-*\bin\java.exe", 
            r"C:\Program Files\Eclipse Adoptium\jdk-*\bin\java.exe",
            r"C:\Program Files\Microsoft\jdk-*\bin\java.exe",
            r"C:\Program Files\OpenJDK\jdk-*\bin\java.exe",
            r"C:\Program Files\Java\jdk-21-allio\bin\java.exe"  # Nuestra instalación
        ]
        
        # Buscar instalaciones existentes y verificar versión
        for pattern in java_paths:
            matches = glob.glob(pattern)
            for match in matches:
                if self.verify_java21_or_higher(match):
                    print(f"[Allio] OK Java compatible encontrado: {match}")
                    return match
        
        # Si no se encuentra Java 21+, mostrar error claro
        print("[Allio] ERROR No se encontró Java 21 o superior")
        print("[Allio] 💡 Se requiere Java 21+ para Minecraft 1.21.10 con Fabric")
        return None
    
    def verify_java21_or_higher(self, java_exe):
        """Verifica que el ejecutable sea Java 21 o superior"""
        try:
            result = subprocess.run([java_exe, '-version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                version_line = result.stderr.split('\n')[0] if result.stderr else result.stdout.split('\n')[0]
                print(f"[Allio] Verificando Java: {version_line}")
                
                # Extraer número de versión principal
                import re
                version_match = re.search(r'version "(\d+)', version_line)
                if version_match:
                    major_version = int(version_match.group(1))
                    # Java 25 tiene problemas con GLFW en Minecraft, usar solo 21-24
                    if major_version >= 21 and major_version <= 24:
                        print(f"[Allio] OK Java {major_version} es compatible con Minecraft 1.21.10")
                        return True
                    elif major_version >= 25:
                        print(f"[Allio] AVISO Java {major_version} es muy nueva y puede causar crashes con GLFW")
                        return False
                    else:
                        print(f"[Allio] ERROR Java {major_version} es demasiado antigua para Minecraft 1.21.10")
                        return False
                
                # Fallback para detectar versiones específicas (solo 21-24)
                if any(v in version_line.lower() for v in ['21.', '22.', '23.', '24.', 'openjdk 21', 'openjdk 22', 'openjdk 23', 'openjdk 24']):
                    return True
                    
        except Exception as e:
            print(f"[Allio] Error verificando Java: {e}")
        return False
    
    def prompt_java21_installation(self):
        """Pregunta al usuario si quiere instalar Java 21 automáticamente"""
        from PyQt6.QtWidgets import QMessageBox, QPushButton
        
        msgBox = QMessageBox(self)
        msgBox.setWindowTitle("Java 21 Requerido")
        msgBox.setText("Minecraft 1.21.10 requiere Java 21 para ejecutarse.")
        msgBox.setInformativeText("¿Quieres que Allio Client descargue e instale Java 21 automáticamente?")
        msgBox.setIcon(QMessageBox.Icon.Question)
        
        # Botones personalizados
        install_btn = msgBox.addButton("Instalar Automáticamente", QMessageBox.ButtonRole.AcceptRole)
        manual_btn = msgBox.addButton("Instalar Manualmente", QMessageBox.ButtonRole.RejectRole)
        cancel_btn = msgBox.addButton("Cancelar", QMessageBox.ButtonRole.DestructiveRole)
        
        msgBox.setDefaultButton(install_btn)
        msgBox.exec()
        
        clicked_button = msgBox.clickedButton()
        
        if clicked_button == install_btn:
            return self.install_java21_automatically()
        elif clicked_button == manual_btn:
            self.show_manual_java21_instructions()
            return None
        else:
            return None
    
    def install_java21_automatically(self):
        """Instala Java 21 automáticamente usando nuestro instalador"""
        try:
            from PyQt6.QtWidgets import QProgressDialog
            from PyQt6.QtCore import Qt
        except Exception as qt_err:
            QMessageBox.critical(
                self,
                "Dependencias faltantes",
                f"No se pudo inicializar el instalador automático de Java 21 (Qt):\n{qt_err}\n\n"
                "Instala Java 21 manualmente desde https://adoptium.net/"
            )
            return None

        try:
            installer_module = importlib.import_module('java21_installer')
        except ImportError:
            QMessageBox.critical(
                self,
                "Error del Instalador",
                "No se pudo cargar el instalador automático de Java 21.\n\n"
                "Instálalo manualmente desde:\nhttps://adoptium.net/"
            )
            return None

        installer_cls = getattr(installer_module, 'Java21Installer', None)
        if installer_cls is None:
            QMessageBox.critical(
                self,
                "Error del Instalador",
                "El módulo java21_installer no define Java21Installer.\n"
                "Instala Java 21 manualmente desde https://adoptium.net/"
            )
            return None

        progress = QProgressDialog("Instalando Java 21...", "Cancelar", 0, 100, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setWindowTitle("Instalador Java 21")
        progress.setMinimumDuration(0)
        progress.show()

        def update_progress(percent: int) -> bool:
            progress.setValue(percent)
            QApplication.processEvents()
            return not progress.wasCanceled()

        print("[Allio]  Iniciando instalación automática de Java 21...")

        try:
            installer = installer_cls()
            result = installer.install_java21_complete(update_progress)
        except Exception as install_err:
            progress.close()
            QMessageBox.critical(
                self,
                "Error de Instalación",
                f"Error durante la instalación automática:\n{install_err}\n\n"
                "Instala Java 21 manualmente desde https://adoptium.net/"
            )
            return None

        progress.close()

        if result and not progress.wasCanceled():
            QMessageBox.information(
                self,
                "Instalación Completada",
                f"¡Java 21 instalado exitosamente!\n\nUbicación: {result}\n\nAhora puedes lanzar Minecraft 1.21.10."
            )
            return result

        if progress.wasCanceled():
            QMessageBox.information(
                self,
                "Instalación Cancelada",
                "La instalación de Java 21 fue cancelada."
            )
            return None

        QMessageBox.critical(
            self,
            "Error de Instalación",
            "No se pudo instalar Java 21 automáticamente.\n\nInstálalo manualmente desde:\nhttps://adoptium.net/"
        )
        return None
    
    def show_manual_java21_instructions(self):
        """Muestra instrucciones para instalación manual de Java 21"""
        QMessageBox.information(self, "Instalación Manual de Java 21", 
            "Para instalar Java 21 manualmente:\n\n"
            "1. Ve a: https://adoptium.net/\n"
            "2. Selecciona 'Temurin 21 (LTS)'\n"
            "3. Plataforma: Windows x64\n"
            "4. Tipo de paquete: JDK\n"
            "5. Descarga e instala el archivo .msi\n\n"
            "Una vez instalado, reinicia Allio Client.")
        
        # Abrir URL en navegador
        import webbrowser
        webbrowser.open("https://adoptium.net/")

    def find_fabric_loader_jar(self, instance_path):
        """Busca un JAR de Fabric Loader real en la instancia"""
        try:
            # Buscar en diferentes ubicaciones
            search_paths = [
                os.path.join(instance_path, '.fabric', 'remappedJars'),
                os.path.join(instance_path, 'mods'),
                instance_path
            ]
            
            import glob
            
            for search_path in search_paths:
                if os.path.exists(search_path):
                    # Buscar archivos fabric-loader específicos
                    patterns = [
                        'fabric-loader-*.jar',
                        'fabric-installer-*.jar',
                        '*fabric*loader*.jar'
                    ]
                    
                    for pattern in patterns:
                        matches = glob.glob(os.path.join(search_path, '**', pattern), recursive=True)
                        if matches:
                            jar_file = matches[0]
                            print(f"[Allio] OK Fabric Loader encontrado: {jar_file}")
                            return jar_file
            
            print("[Allio] AVISO No se encontró Fabric Loader específico")
            return None
            
        except Exception as e:
            print(f"[Allio] Error buscando Fabric Loader: {e}")
            return None

    def find_minecraft_jar(self, versions_dir):
        """Busca el JAR de Minecraft vanilla"""
        try:
            # Versiones a buscar (desde la más nueva)
            versions_to_try = ['1.21.10', '1.21.1', '1.21', '1.20.6', '1.20.4', '1.20.1']
            
            for version in versions_to_try:
                version_path = os.path.join(versions_dir, version, f'{version}.jar')
                if os.path.exists(version_path):
                    print(f"[Allio] OK Minecraft JAR encontrado: {version_path}")
                    return version_path
            
            # Buscar cualquier versión disponible
            import glob
            jar_pattern = os.path.join(versions_dir, '*', '*.jar')
            jar_files = glob.glob(jar_pattern)
            
            if jar_files:
                # Tomar el más reciente
                jar_file = sorted(jar_files)[-1]
                print(f"[Allio] OK Minecraft JAR (genérico) encontrado: {jar_file}")
                return jar_file
            
            print("[Allio] AVISO No se encontró JAR de Minecraft vanilla")
            return None
            
        except Exception as e:
            print(f"[Allio] Error buscando Minecraft JAR: {e}")
            return None

    def create_launch_script(self, java_executable, instance_path, username):
        """Crea un script .bat para lanzar Minecraft con Fabric"""
                
        # Paths importantes
        minecraft_dir = os.path.join(os.getenv('APPDATA', ''), '.minecraft')
        assets_dir = os.path.join(minecraft_dir, 'assets')
        libraries_dir = os.path.join(minecraft_dir, 'libraries')
        
        script = f'''@echo off
echo [AllioClient] Iniciando Minecraft Fabric...
echo [AllioClient] Instancia: PermadeatH
echo [AllioClient] Usuario: {username}
echo.

cd /d "{instance_path}"

"{java_executable}" ^
    -Xmx4G ^
    -Xms1G ^
    -Dminecraft.launcher.brand=AllioClient ^
    -Dminecraft.launcher.version=2.0 ^
    -Djava.library.path="{libraries_dir}" ^
    -Dfile.encoding=UTF-8 ^
    -Duser.country=ES ^
    -Duser.language=es ^
    -jar "{os.path.join(instance_path, 'mods', 'fabric-api-0.135.0+1.21.10.jar')}" ^
    --username "{username}" ^
    --uuid "{uuid}" ^
    --accessToken "null" ^
    --userType "legacy" ^
    --version "1.21.10" ^
    --gameDir "{instance_path}" ^
    --assetsDir "{assets_dir}" ^
    --assetIndex "18"

if errorlevel 1 (
    echo.
    echo [AllioClient] Error al lanzar Minecraft
    pause
) else (
    echo [AllioClient] Minecraft cerrado correctamente
)
'''
        return script

    def find_minecraft_launcher(self):
        """Busca el ejecutable del launcher de Minecraft"""
        launcher_paths = [
            os.path.join(os.getenv('ProgramFiles', ''), 'Minecraft Launcher', 'MinecraftLauncher.exe'),
            os.path.join(os.getenv('ProgramFiles(x86)', ''), 'Minecraft Launcher', 'MinecraftLauncher.exe'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), 'Programs', 'Minecraft Launcher', 'MinecraftLauncher.exe'),
        ]
        
        for path in launcher_paths:
            if os.path.exists(path):
                return path
        
        return None

    def find_java_executable(self):
        """Busca la versión más moderna de Java compatible con Minecraft 1.21.10"""
        try:
            import glob
            import re
            
            # Paths donde buscar Java (priorizando versiones modernas)
            java_search_patterns = [
                # Minecraft Launcher runtime (más probable que tenga Java 21+)
                r'C:\Program Files\Minecraft Launcher\runtime\**\java.exe',
                r'C:\Program Files (x86)\Minecraft Launcher\runtime\**\java.exe',
                # OpenJDK/Eclipse Adoptium (versiones modernas)
                r'C:\Program Files\Eclipse Adoptium\**\java.exe',
                r'C:\Program Files\OpenJDK\**\java.exe',
                # Java estándar (puede ser antigua)
                r'C:\Program Files\Java\**\java.exe',
                r'C:\Program Files (x86)\Java\**\java.exe'
            ]
            
            best_java = None
            best_version = 0
            
            print("[Allio] Buscando versión de Java compatible con Minecraft 1.21.10...")
            
            for pattern in java_search_patterns:
                matches = glob.glob(pattern, recursive=True)
                for match in matches:
                    if 'bin' in match and match.endswith('java.exe'):
                        try:
                            # Obtener versión de Java
                            result = subprocess.run([match, '-version'], 
                                                  capture_output=True, text=True, timeout=5)
                            
                            if result.returncode == 0:
                                version_line = result.stderr.split('\n')[0] if result.stderr else result.stdout.split('\n')[0]
                                
                                # Extraer número de versión
                                version_match = re.search(r'(\d+)\.(\d+)\.(\d+)', version_line)
                                if not version_match:
                                    version_match = re.search(r'"(\d+)"', version_line)  # Formato Java 9+
                                
                                if version_match:
                                    if len(version_match.groups()) >= 3:
                                        major = int(version_match.group(1))
                                        minor = int(version_match.group(2))
                                        
                                        # Convertir formato 1.8.0 a 8
                                        if major == 1:
                                            java_version = minor
                                        else:
                                            java_version = major
                                    else:
                                        java_version = int(version_match.group(1))
                                    
                                    print(f"[Allio] Encontrado Java {java_version}: {match}")
                                    
                                    # Minecraft 1.21.10 requiere Java 21+
                                    if java_version >= 21:
                                        print(f"[Allio] OK Java {java_version} es compatible con Minecraft 1.21.10")
                                        if java_version > best_version:
                                            best_java = match
                                            best_version = java_version
                                    elif java_version >= 17:
                                        print(f"[Allio] AVISO Java {java_version} podría funcionar (recomendado: Java 21+)")
                                        if best_version < 17:  # Solo usar si no hay mejor opción
                                            best_java = match
                                            best_version = java_version
                                    else:
                                        print(f"[Allio] ERROR Java {java_version} es demasiado antigua para Minecraft 1.21.10")
                                        
                        except Exception as e:
                            continue
            
            # Si no encontramos Java moderna, buscar cualquier Java como fallback
            if not best_java:
                print("[Allio] AVISO No se encontró Java 21+, buscando cualquier versión...")
                # Usar la búsqueda antigua como fallback
                java_paths = [
                    r'C:\Program Files (x86)\Java\jre1.8.0_441\bin\java.exe',
                    r'C:\Program Files\Java\jre1.8.0_441\bin\java.exe',
                ]
                
                for path in java_paths:
                    if os.path.exists(path):
                        print(f"[Allio] AVISO Usando Java antigua: {path}")
                        print("[Allio] 💡 Para mejor compatibilidad, instala Java 21+ desde: https://adoptium.net/")
                        return path
                
                # Intentar desde PATH
                try:
                    result = subprocess.run(['java', '-version'], 
                        capture_output=True, text=True, check=True)
                    print("[Allio] AVISO Usando Java del PATH")
                    return 'java'
                except Exception:
                    pass
            else:
                print(f"[Allio] OK Usando Java {best_version}: {best_java}")
                return best_java
            
            print("[Allio] ERROR No se encontró ninguna versión de Java")
            return None
                
        except Exception as e:
            print(f"[Allio] ERROR Error buscando Java: {e}")
            return None

    def get_minecraft_java_username(self):
        """Obtiene el username de Minecraft Java desde la configuración"""
        try:
            config_file = "allio_config.json"
            if os.path.exists(config_file):
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    username = config.get('minecraft_java_username', '') or config.get('gamertag', '')
                    if username and username != "Sin sesión":
                        print(f"[Allio] Username de Minecraft Java: {username}")
                        return username
            
            # Fallback al username actual
            username = getattr(self, '_username', '')
            if username and username != "Sin sesión":
                return username
                
            return None
            
        except Exception as e:
            print(f"[Allio] Error obteniendo username: {e}")
            return None

    def build_fabric_launch_command(self, java_exe, fabric_jar, instance_path, username):
        """Construye el comando de lanzamiento para Fabric"""
        
        # Paths importantes
        game_dir = instance_path
        assets_dir = os.path.join(os.getenv('APPDATA', ''), '.minecraft', 'assets')
        libraries_dir = os.path.join(os.getenv('APPDATA', ''), '.minecraft', 'libraries')
        
        # Crear directorio de assets si no existe
        os.makedirs(assets_dir, exist_ok=True)
        os.makedirs(libraries_dir, exist_ok=True)
        
        # UUID del usuario (desde los archivos de save)
        uuid = "2e82d582-c5dd-44a0-887e-e13661fc2866"  # Tu UUID de los saves
        
        cmd = [
            java_exe,
            '-Xmx4G',  # 4GB de RAM
            '-Xms1G',  # 1GB inicial
            '-Dminecraft.launcher.brand=AllioClient',
            '-Dminecraft.launcher.version=2.0',
            f'-Djava.library.path={libraries_dir}',
            '-cp', self.build_classpath(instance_path, libraries_dir),
            'net.fabricmc.loader.impl.launch.knot.KnotClient',
            '--username', username,
            '--uuid', uuid,
            '--accessToken', 'null',
            '--userType', 'legacy',
            '--version', '1.21.10',
            '--gameDir', game_dir,
            '--assetsDir', assets_dir,
            '--assetIndex', '18',
        ]
        
        return cmd

    def build_classpath(self, instance_path, libraries_dir):
        """Construye el classpath para Fabric"""
        classpath_parts = []
        
        # Agregar JAR del juego (versión vanilla)
        minecraft_jar = os.path.join(os.getenv('APPDATA', ''), '.minecraft', 'versions', '1.21.10', '1.21.10.jar')
        if os.path.exists(minecraft_jar):
            classpath_parts.append(minecraft_jar)
        
        # Agregar mods de la instancia
        mods_path = os.path.join(instance_path, 'mods')
        if os.path.exists(mods_path):
            import glob
            mod_jars = glob.glob(os.path.join(mods_path, '*.jar'))
            classpath_parts.extend(mod_jars)
        
        # Agregar librerías de Fabric (si existen)
        if os.path.exists(libraries_dir):
            import glob
            lib_jars = glob.glob(os.path.join(libraries_dir, '**', '*.jar'), recursive=True)
            classpath_parts.extend(lib_jars)
        
        return os.pathsep.join(classpath_parts) if classpath_parts else ''

    def launch_default_minecraft_java(self):
        """Lanza el launcher oficial de Minecraft Java como fallback"""
        try :
            # Intentar abrir el launcher oficial de Minecraft Java
            try :
                # Buscar en rutas comunes del launcher de Minecraft Java
                java_launcher_paths = [
                    os.path.join(os.getenv('ProgramFiles', ''), 'Minecraft Launcher', 'MinecraftLauncher.exe'),
                    os.path.join(os.getenv('ProgramFiles(x86)', ''), 'Minecraft Launcher', 'MinecraftLauncher.exe'),
                    os.path.join(os.getenv('LOCALAPPDATA', ''), 'Programs', 'Minecraft Launcher', 'MinecraftLauncher.exe'),
                    os.path.join(os.getenv('APPDATA', ''), '.minecraft', 'launcher', 'MinecraftLauncher.exe')
                ]
                
                for launcher_path in java_launcher_paths:
                    if launcher_path and os.path.exists(launcher_path):
                        print(f"[Allio] Lanzando Minecraft Java desde: {launcher_path}")
                        subprocess.Popen([launcher_path], creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                        return True
                        
                # Intentar con comando directo si está en PATH
                try:
                    subprocess.run(['MinecraftLauncher.exe'], check=False, 
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                    return True
                except Exception:
                    pass
                    
            except Exception as e:
                print(f"[Allio] Error intentando lanzar Minecraft Java: {e}")

            # Si no se encuentra el launcher, informar al usuario
            QMessageBox .information (self ,"Abrir Minecraft Java","No se pudo encontrar Minecraft Java Edition automáticamente.\n\nPor favor:\n1. Asegúrate de tener Minecraft Java Edition instalado\n2. Instala el launcher oficial desde minecraft.net\n3. O ábrelo manualmente")
            return False 
        except Exception as e :
            QMessageBox .warning (self ,"Abrir Minecraft Java",f"Error al intentar abrir Minecraft Java: {e}")
            return False 

    def paintEvent (self ,event ):

        p =QPainter (self )
        p .setRenderHint (QPainter .RenderHint .SmoothPixmapTransform )
        if self .bg :
            scaled =self .bg .scaled (self .size (),Qt .AspectRatioMode .KeepAspectRatioByExpanding ,Qt .TransformationMode .SmoothTransformation )
            x =(self .width ()-scaled .width ())//2 
            y =(self .height ()-scaled .height ())//2 
            p .drawPixmap (x ,y ,scaled )
        else :
            p .fillRect (self .rect (),QColor ("#002b2b"))
            p .setPen (Qt .GlobalColor .cyan )
            p .setFont (QFont ("Avenir, Segoe UI",22 ,QFont .Weight .Bold ))
            p .drawText (self .rect (),Qt .AlignmentFlag .AlignCenter ,"fondo.png no encontrado")

    def resizeEvent (self ,e ):

        try :
            if hasattr (self ,"_floating"):
                margin =12 
                fw =self ._floating .width ()
                fh =self ._floating .height ()

                bottom_h =getattr (self ,"_bottom_bar",None ).height ()if getattr (self ,"_bottom_bar",None )is not None else 0 

                y =max (margin ,self .height ()-fh -bottom_h -margin )
                self ._floating .move (margin ,y )
                try :
                    self ._floating .raise_ ()
                except Exception :
                    pass 
        except Exception :
            pass 

        super ().resizeEvent (e )


        try:
            if hasattr(self, 'play_btn') and self.play_btn is not None:
                bottom_bar_h = 110
                # reserve space for any floating widget (avatars/buttons) so the play button doesn't overlap
                floating_h = 0
                try:
                    if hasattr(self, '_floating') and self._floating is not None:
                        floating_h = self._floating.height()
                except Exception:
                    floating_h = 0

                reserved_bottom = bottom_bar_h + floating_h + 12

                x = max(12, (self.width() - self.play_btn.width()) // 2)
                y = max(8, self.height() - reserved_bottom - self.play_btn.height())

                # move the play button a bit lower (user requested it lower)
                play_extra_down = 70
                # apply extra down and clamp so it stays within the widget
                y = y + play_extra_down
                y = max(8, min(y, max(8, self.height() - self.play_btn.height() - 8)))

                self.play_btn.move(x, y)
                try:
                    if hasattr(self, 'play_tile') and self.play_tile is not None:
                        tile_w = self.play_tile.width()
                        tile_h = self.play_tile.height()
                        btn_h = self.play_btn.height()
                        # colocar el tile centrado verticalmente respecto al botón y asegurarlo visible
                        y_tile = y - max(0, (tile_h - btn_h) // 2) - 6
                        bottom_bar_h2 = 110
                        floating_h2 = 0
                        try:
                            if hasattr(self, '_floating') and self._floating is not None:
                                floating_h2 = self._floating.height()
                        except Exception:
                            floating_h2 = 0
                        reserved_bottom2 = bottom_bar_h2 + floating_h2 + 12
                        y_tile = max(8, min(self.height() - reserved_bottom2 - tile_h, y_tile))
                        self.play_tile.move(x, y_tile)
                except Exception:
                    pass
                try:
                    self.play_btn.raise_()
                    if hasattr(self, 'play_tile') and self.play_tile is not None:
                        self.play_tile.raise_()
                except Exception:
                    pass
        except Exception:
            pass

    def _on_avatar_ready (self ,face :QPixmap ):
        """Recibe avatar circular ya preparado desde el launcher y lo aplica al botón pequeño."""
        try :
            if face and not face .isNull ()and hasattr (self ,"_small_avatar"):

                self ._small_avatar .setIcon (QIcon (face ))
                self ._small_avatar .setIconSize (face .size ())
        except Exception as e :
            print (f"[MapWidget] Error aplicando avatar pequeño: {e}")

    def set_background_image (self ,filename :str ):
        """Intenta cargar resource_path(filename) y usarlo como fondo; si no existe, no cambia.
        Actualiza además la visibilidad del botón 'Jugar' para fondos específicos."""
        try:
            path = resource_path(filename)
            if os.path.exists(path):
                pm = QPixmap(path)
                if not pm.isNull():
                    self.bg = pm
                    self._bg_filename = filename
                    try:
                        if hasattr(self, "play_btn"):
                            # show play button for the main background or for the
                            # specific instance background 'fondoinstacia3.png'
                            show_play = (filename == BACKGROUND_FILE) or (filename == "fondoinstacia3.png")
                            try:
                                # If we're currently showing the play_tile (lanzamiento), don't reveal the floating button
                                if hasattr(self, 'play_tile') and self.play_tile is not None and self.play_tile.isVisible():
                                    show_play = False
                            except Exception:
                                pass
                            try:
                                owner = self._resolve_launcher_owner()
                                if owner is not None and getattr(owner, '_is_launching', False):
                                    show_play = False
                            except Exception:
                                pass
                            self.play_btn.setVisible(show_play)
                    except Exception:
                        pass
                    self.update()
                    print(f"[MapWidget] Fondo cambiado a: {filename}")

                    # update instance buttons visibility/styles
                    try:
                        idx = None
                        if filename == BACKGROUND_FILE:
                            idx = 0
                        elif filename == "fondoinstacia3.png":
                            idx = 1

                        if idx is not None and hasattr(self, 'inst_buttons'):
                            # keep all instance buttons visible; only apply the blue border
                            # for the primary background (idx == 0). Secondary instances
                            # should remain transparent.
                            for i, b in enumerate(self.inst_buttons):
                                try:
                                    b.setVisible(True)
                                    try:
                                        if i == 0 and idx == 0:
                                            # only highlight the first button when main bg is selected
                                            b.setStyleSheet("background: transparent; border: 3px solid #3aa8ff; border-radius:8px;")
                                        else:
                                            b.setStyleSheet("background: transparent; border: none;")
                                    except Exception:
                                        pass
                                except Exception:
                                    pass
                    except Exception:
                        pass
            else:
                self._bg_filename = None
                try:
                    if hasattr(self, "play_btn"):
                        self.play_btn.setVisible(False)
                except Exception:
                    pass
                print(f"[MapWidget] Fondo '{filename}' no encontrado en resources.")
        except Exception as e:
            print(f"[MapWidget] Error cargando fondo '{filename}': {e}")

    def show_instance_button (self ,index :int ,only_this :bool =False ,save :bool =True ):
        """Muestra (o oculta) el botón de instancia index (0-based).
        Si only_this True, oculta los demás; si False, solo cambia el estado del indicado.
        Por defecto guarda la configuración (save=True). Pasar save=False para restauraciones
        donde no se desea que la acción dispare un guardado inmediato en disco."""
        try :
            if not hasattr (self ,"inst_buttons"):
                return 
            for i ,b in enumerate (self .inst_buttons ):
                if i ==index :
                    b .setVisible (True )
                elif only_this :
                    b .setVisible (False )


            try :
                # Si el launcher principal está en estado de 'lanzamiento' (play_tile visible),
                # no volver a mostrar el botón Play aunque el usuario cambie la instancia.
                show_play = (index in (0, 1))
                # Comprobar si este MapWidget ya está mostrando el play_tile (estado de lanzamiento)
                try:
                    if hasattr(self, 'play_tile') and self.play_tile is not None and self.play_tile.isVisible():
                        show_play = False
                except Exception:
                    pass

                # Además comprobar el flag persistente en el launcher (_is_launching)
                try:
                    owner = self._resolve_launcher_owner()
                    if owner is not None and getattr(owner, '_is_launching', False):
                        show_play = False
                except Exception:
                    pass

                if hasattr (self ,'play_btn'):
                    self .play_btn .setVisible (show_play )
            except Exception :
                pass 
        except Exception :
            pass 

        try :
            if save :
                parent =self .parent ()if self .parent ()is not None else self .window ()
                if parent is not None and hasattr (parent ,"_username")and getattr (parent ,"_username","")and getattr (parent ,"_username","")!="Sin sesión":
                    try :
                        if hasattr (parent ,"save_config"):
                            parent .save_config ()
                    except Exception :
                        pass 
        except Exception :
            pass 

class BlackLogoWidget (QWidget ):
    # Signal to request showing the loading UI from worker threads (queued to GUI thread)
    showLoadingRequested = pyqtSignal(str)
    def __init__ (self ,parent =None ,auto_gamertag :str =None ):
        super ().__init__ (parent )
        self .setObjectName ("mainBg")
        self .bg_path =resource_path ("iniciofondo.png")
        self .bg =QPixmap (self .bg_path )if os .path .exists (self .bg_path )else None 

        self ._auto_gamertag =auto_gamertag 
        # Guard to prevent concurrent login flows
        self._login_in_progress = False

        layout =QVBoxLayout (self )
        layout .setContentsMargins (0 ,0 ,0 ,0 )
        layout .setSpacing (0 )

        try:
            if not globals().get('USE_NATIVE_TITLEBAR', False):
                self .titleBar = TitleBar(self)
            else:
                self .titleBar = None
        except Exception:
            self .titleBar = None

        if getattr(self, 'titleBar', None) is not None:
            layout .addWidget (self .titleBar )

        main_window =parent if parent is not None else self .window ()
        if main_window is not None and getattr(self, 'titleBar', None) is not None:
            try:
                self .titleBar .minimizeRequested .connect (lambda :main_window .showMinimized ()if hasattr (main_window ,'showMinimized')else None )
                self .titleBar .closeRequested .connect (lambda :main_window .close ()if hasattr (main_window ,'close')else None )
                self .titleBar .maximizeRequested .connect (lambda :main_window .toggle_max_restore ()if hasattr (main_window ,'toggle_max_restore')else None )
            except Exception:
                pass

        content_container =QWidget ()
        content_l =QVBoxLayout (content_container )
        content_l .setContentsMargins (0 ,0 ,0 ,0 )
        content_l .setSpacing (8 )
        content_l .setAlignment (Qt .AlignmentFlag .AlignCenter )

        self .title_top =QLabel ()
        self .title_top .setAlignment (Qt .AlignmentFlag .AlignCenter )
        self .title_top .setObjectName ("loginTitleTop")

        self .title_top .setStyleSheet ("color: white; font: 800 36px 'Segoe UI';")
        self .title_top .setText (
        '<span style="color: white;">PLEASE </span>'
        '<span style="color: #cd1955;">LOG-IN</span>'
        )
        content_l .addWidget (self .title_top )

        self .title_bottom =QLabel ("WITH YOUR ACCOUNT")
        self .title_bottom .setAlignment (Qt .AlignmentFlag .AlignCenter )
        self .title_bottom .setObjectName ("loginTitleBottom")
        self .title_bottom .setStyleSheet ("color: white; font: 800 28px 'Segoe UI';")
        content_l .addWidget (self .title_bottom )

        content_l .addSpacing (18 )

        self .xbox_button =QPushButton ("Microsoft Account")

        self .xbox_button .setStyleSheet ("background: #cd1955; color: white; font: 600 18px 'Segoe UI'; padding: 10px 20px; border-radius: 8px;")
        self .xbox_button .setIcon (QIcon (resource_path ("xbox.png")))
        self .xbox_button .setIconSize (QSize (30 ,30 ))
        self .xbox_button .setCursor (Qt .CursorShape .PointingHandCursor )

        content_l .addWidget (self .xbox_button ,alignment =Qt .AlignmentFlag .AlignCenter )

        # Connect signal to parent's show_loading_with if available (ensures queued connection)
        try:
            if parent is not None and hasattr(parent, 'show_loading_with'):
                try:
                    self.showLoadingRequested.connect(parent.show_loading_with)
                except Exception:
                    pass
        except Exception:
            pass

        layout .addWidget (content_container ,1 ,Qt .AlignmentFlag .AlignCenter )

        # Servidor Flask embebido para capturar el code de autorización
        _flask_app = Flask(__name__)
        _auth_code = {"val": None, "verifier": None}

        @_flask_app.route('/redirect')
        def _capture_code():
            try:
                # Log full request for debugging (URL + args)
                try:
                    print(f"[Allio OAuth] Redirect request URL: {request.url}")
                    print(f"[Allio OAuth] Redirect args: {dict(request.args)}")
                except Exception:
                    pass

                # Aceptar GET o POST según lo que Microsoft utilice
                code = None
                state_received = None
                error_received = None
                try:
                    if request.method == 'POST':
                        code = request.form.get('code')
                        state_received = request.form.get('state')
                        error_received = request.form.get('error')
                    else:
                        code = request.args.get('code')
                        state_received = request.args.get('state')
                        error_received = request.args.get('error')
                except Exception:
                    # Fallback simple
                    code = request.args.get('code')
                    state_received = request.args.get('state')

                if error_received:
                    print(f"[Allio OAuth] Error recibido en redirect: {error_received}")
                    _auth_code['val'] = '__error__:' + str(error_received)

                # Registrar state y compararlo si fue generado por nosotros
                try:
                    stored_state = _auth_code.get('state')
                    if state_received:
                        print(f"[Allio OAuth] State recibido: {state_received} (guardado={stored_state})")
                    if stored_state and state_received and state_received != stored_state:
                        print(f"[Allio OAuth] WARNING: state no coincide (posible CSRF o mismatch).")
                except Exception:
                    pass

                if code and _auth_code["val"] is None:
                    # Solo aceptar el PRIMER código que llegue
                    _auth_code["val"] = code
                    print(f"[Allio OAuth] Código capturado: {code[:20]}...")

                return "Success! You can now close this window and go back to the Allio Launcher."
            except Exception as e:
                print(f"[Allio OAuth] Error en /redirect: {e}")
                return "Error processing redirect. Check launcher logs.", 500

        def _run_flask():
            try:
                # bind explicitly to localhost and disable reloader for embedded use
                _flask_app.run(host='127.0.0.1', port=MS_FLASK_PORT, debug=False, use_reloader=False)
            except Exception as e:
                print(f"[Allio] Flask server error: {e}")

        def _generate_pkce_pair():
            code_verifier = base64.urlsafe_b64encode(os.urandom(64)).decode().rstrip("=")
            code_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).decode().rstrip("=")
            return code_verifier, code_challenge

        def _authenticate_with_msal():
            """Autenticar con Microsoft usando MSAL (con caché de tokens)"""
            try:
                print("[Allio MSAL] Creando aplicación MSAL...")
                
                # Usar un archivo de caché para guardar tokens
                cache_file = os.path.join(os.getenv('APPDATA', ''), 'AllioClient', 'msal_token_cache.bin')
                cache = msal.SerializableTokenCache()
                
                # Cargar caché si existe
                if os.path.exists(cache_file):
                    try:
                        with open(cache_file, 'r') as f:
                            cache.deserialize(f.read())
                        print("[Allio MSAL] Caché de tokens cargada")
                    except Exception as e:
                        print(f"[Allio MSAL] No se pudo cargar caché: {e}")
                
                app = msal.PublicClientApplication(
                    MS_CLIENT_ID,
                    authority="https://login.microsoftonline.com/consumers",
                    token_cache=cache
                )
                
                # Intentar obtener token silenciosamente (sin interacción)
                accounts = app.get_accounts()
                result = None
                
                if accounts:
                    print(f"[Allio MSAL] Encontradas {len(accounts)} cuentas en caché")
                    print("[Allio MSAL] Autenticando automáticamente...")
                    result = app.acquire_token_silent(MS_OAUTH_SCOPES, account=accounts[0])
                    
                    if result and "access_token" in result:
                        print("[Allio MSAL] ✅ Sesión iniciada automáticamente (sin código)")
                
                # Si no hay token en caché o expiró, el sistema caerá al OAuth tradicional
                if not result:
                    print("[Allio MSAL] No hay sesión guardada - continuando con OAuth")
                    return None  # Permitir que OAuth tradicional tome el control
                
                if not result or "access_token" not in result:
                    print(f"[Allio MSAL] Error: {result.get('error_description', 'Sin token')}")
                    return None
                
                # Guardar caché para próxima vez
                if cache.has_state_changed:
                    try:
                        os.makedirs(os.path.dirname(cache_file), exist_ok=True)
                        with open(cache_file, 'w') as f:
                            f.write(cache.serialize())
                        print("[Allio MSAL] Caché de tokens guardada")
                    except Exception as e:
                        print(f"[Allio MSAL] No se pudo guardar caché: {e}")
                
                # Extraer información del usuario
                id_claims = result.get("id_token_claims", {})
                user_email = id_claims.get("preferred_username", "")
                user_name = id_claims.get("name", "")
                
                print(f"[Allio MSAL] ✓ Autenticación exitosa")
                if user_email:
                    print(f"[Allio MSAL] Email: {user_email}")
                if user_name:
                    print(f"[Allio MSAL] Nombre: {user_name}")
                
                return {
                    "access_token": result["access_token"],
                    "refresh_token": result.get("refresh_token", ""),
                    "expires_in": result.get("expires_in", 3600),
                    "token_type": "Bearer",
                    "scope": MS_OAUTH_SCOPE,
                    "ext_expires_in": result.get("ext_expires_in", 3600),
                    "_msal_user_email": user_email,
                    "_msal_user_name": user_name
                }
                
            except Exception as e:
                print(f"[Allio MSAL] Error: {e}")
                import traceback
                traceback.print_exc()
                return None

        def _login_flow_in_thread():
            if getattr(self, '_login_in_progress', False):
                print('[Allio] Login ya en progreso, ignorando nueva petición.')
                return
            self._login_in_progress = True
            mw = parent if parent is not None else self.window()
            try:
                # PRIMERO: Intentar importar sesión desde launcher oficial de Microsoft
                print("[Allio] Buscando sesión existente en launcher de Microsoft...")
                minecraft_dir = os.path.join(os.getenv('APPDATA', ''), '.minecraft')
                official_session = load_official_launcher_session(minecraft_dir)
                
                if official_session and official_session.get('minecraft_username'):
                    print(f"[Allio] OK Sesión de Microsoft encontrada: {official_session['minecraft_username']}")
                    print(f"[Allio] UUID: {official_session.get('minecraft_uuid')}")
                    
                    # Usar directamente la sesión oficial
                    final_username = official_session['minecraft_username']
                    
                    # Actualizar sesión
                    if mw is not None and hasattr(mw, 'update_auth_session'):
                        mw.update_auth_session(official_session)
                        print(f"[Allio] Sesión importada desde Microsoft Store para {final_username} (online)")
                        if hasattr(mw, 'save_config'):
                            try:
                                mw.save_config()
                            except Exception as save_err:
                                print(f"[Allio] Advertencia guardando configuración: {save_err}")
                    
                    # Abrir ventana de instancias
                    if mw is not None:
                        try:
                            setattr(mw, '_open_instances_on_success', True)
                            print(f"[Allio] parent flag _open_instances_on_success set True for '{final_username}'")
                        except Exception:
                            pass

                        try:
                            self.showLoadingRequested.emit(final_username)
                            print(f"[Allio] showLoadingRequested.emit done for '{final_username}'")
                        except Exception as e:
                            print(f"[Allio] showLoadingRequested.emit failed: {e}")

                        try:
                            QTimer.singleShot(200, lambda: mw.show_loading_with(final_username))
                            print(f"[Allio] QTimer.singleShot scheduled parent.show_loading_with for '{final_username}'")
                        except Exception as e:
                            print(f"[Allio] Error programando show_loading_with: {e}")
                    
                    return  # ¡Terminamos! No necesitamos OAuth
                
                print("[Allio] No se encontró sesión en Microsoft Store, iniciando OAuth...")
                
                # INTENTAR MSAL PRIMERO (Device Code Flow)
                print("[Allio] Intentando autenticación con MSAL...")
                tokens = _authenticate_with_msal()
                
                # Si MSAL falla, usar Flask OAuth (fallback)
                if not tokens:
                    print("[Allio] MSAL no disponible, usando OAuth tradicional...")
                    
                    try:
                        self.xbox_button.setEnabled(False)
                    except Exception:
                        pass

                    # Generar code_verifier UNA VEZ y guardarlo
                    import secrets
                    code_verifier, code_challenge = _generate_pkce_pair()
                    _auth_code["verifier"] = code_verifier  # Guardar para usar después
                    _auth_code["val"] = None  # Resetear código
                    # Generar state para mitigar CSRF y permitir verificación
                    state = secrets.token_urlsafe(16)
                    _auth_code['state'] = state
                    
                    # Forzamos redirect normalizada
                    redirect_val = _get_normalized_redirect()
                    params = {
                        "client_id": MS_CLIENT_ID,
                        "response_type": "code",
                        "state": state,
                        "redirect_uri": redirect_val,
                        "response_mode": "query",
                        "scope": MS_OAUTH_SCOPE,
                        "prompt": "consent",
                        "code_challenge": code_challenge,
                        "code_challenge_method": "S256",
                    }
                    auth_url = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?" + urllib.parse.urlencode(params)
                    _append_run_log(f"Auth URL: {auth_url}")
                    print(f"[Allio OAuth] Auth URL: {auth_url}")

                    # Iniciar servidor Flask
                    threading.Thread(target=_run_flask, daemon=True).start()
                    time.sleep(0.5)  # Dar tiempo al servidor para iniciar
                    
                    print("[Allio] Abriendo navegador para iniciar sesión...")
                    webbrowser.open(auth_url)

                    start_ts = time.time()
                    max_wait = 120.0
                    while _auth_code["val"] is None and (time.time() - start_ts) < max_wait:
                        threading.Event().wait(0.1)

                    if _auth_code["val"] is None:
                        print("[Allio] No se recibió código de autorización (timeout).")
                        return

                    code = _auth_code["val"]
                    stored_verifier = _auth_code.get("verifier", code_verifier)
                    print(f"[Allio] Código recibido. Intercambiando por tokens...")

                    data = {
                        "client_id": MS_CLIENT_ID,
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": MS_REDIRECT_URI,
                        "code_verifier": stored_verifier,
                        "scope": MS_OAUTH_SCOPE,
                    }
                    resp = requests.post(MS_TOKEN_URL, data=data, timeout=20)
                    try:
                        resp.raise_for_status()
                    except Exception as token_err:
                        try:
                            print(f"[Allio] Error HTTP tokens: {token_err} -> {resp.text}")
                        except Exception:
                            print(f"[Allio] Error HTTP tokens: {token_err}")
                        return

                    tokens = resp.json()
                    try:
                        print(f"[Allio OAuth] Tokens recibidos: claves={list(tokens.keys())}")
                    except Exception:
                        pass

                    if "access_token" not in tokens:
                        print(f"[Allio] Error al obtener tokens: {tokens}")
                        return
                else:
                    # MSAL exitoso, tokens ya contiene access_token y datos del usuario
                    print(f"[Allio MSAL] ✓ Usando tokens de MSAL")

                access_token = tokens["access_token"]
                
                # Extraer información del usuario (de MSAL o del token)
                email_username = None
                ms_account_email = None
                ms_display_name = None
                
                # PRIMERO: Verificar si MSAL proporcionó la información del usuario
                if "_msal_user_email" in tokens:
                    ms_account_email = tokens["_msal_user_email"]
                    ms_display_name = tokens.get("_msal_user_name", "")
                    
                    if ms_account_email:
                        username_part = ms_account_email.split('@')[0]
                        import re
                        email_username = re.sub(r'[^a-zA-Z0-9_]', '', username_part)[:16]
                        print(f"[Allio MSAL] ✓ Email obtenido de MSAL: {ms_account_email}, username: {email_username}")
                    
                    if ms_display_name and not email_username:
                        import re
                        email_username = re.sub(r'[^a-zA-Z0-9_]', '', ms_display_name)[:16]
                        print(f"[Allio MSAL] ✓ Nombre obtenido de MSAL: {ms_display_name}, username: {email_username}")
                
                # SEGUNDO: Si hay id_token (OAuth), decodificarlo para obtener email/nombre
                if not email_username:
                    raw_id_token = tokens.get("id_token")
                    if raw_id_token:
                        try:
                            print("[Allio MS] Decodificando id_token...")
                            parts = raw_id_token.split('.')
                            if len(parts) >= 2:
                                payload_part = parts[1]
                                padding = '=' * (-len(payload_part) % 4)
                                payload_bytes = base64.urlsafe_b64decode(payload_part + padding)
                                token_data = json.loads(payload_bytes.decode('utf-8'))

                                print(f"[Allio MS] id_token decodificado. Claves: {list(token_data.keys())}")

                                candidate_email = token_data.get('preferred_username') or token_data.get('email')
                                candidate_name = token_data.get('name') or token_data.get('given_name')

                                if candidate_email:
                                    username_part = candidate_email.split('@')[0]
                                    import re
                                    email_username = re.sub(r'[^a-zA-Z0-9_]', '', username_part)[:16]
                                    ms_account_email = candidate_email
                                    print(f"[Allio MS] ✓ Email desde id_token: {candidate_email} -> {email_username}")
                                elif candidate_name:
                                    import re
                                    email_username = re.sub(r'[^a-zA-Z0-9_]', '', candidate_name)[:16]
                                    ms_display_name = candidate_name
                                    print(f"[Allio MS] ✓ Nombre desde id_token: {candidate_name} -> {email_username}")
                            else:
                                print(f"[Allio MS] id_token inválido (partes={len(parts)})")
                        except Exception as id_err:
                            print(f"[Allio MS] Error decodificando id_token: {id_err}")

                # TERCERO: Como fallback final, intentar decodificar el access_token
                if not email_username:
                    try:
                        print("[Allio MS] Intentando decodificar access_token...")
                        parts = access_token.split('.')
                        if len(parts) >= 2:
                            payload_part = parts[1]
                            padding = '=' * (-len(payload_part) % 4)
                            payload_bytes = base64.urlsafe_b64decode(payload_part + padding)
                            token_data = json.loads(payload_bytes.decode('utf-8'))
                            
                            print(f"[Allio MS] Token decodificado. Claves disponibles: {list(token_data.keys())}")
                            
                            # Buscar email en múltiples campos posibles
                            email = (token_data.get('email') or 
                                    token_data.get('upn') or 
                                    token_data.get('unique_name') or 
                                    token_data.get('preferred_username') or '')
                            
                            name = token_data.get('name', '')
                            
                            if email:
                                username_part = email.split('@')[0]
                                import re
                                email_username = re.sub(r'[^a-zA-Z0-9_]', '', username_part)[:16]
                                ms_account_email = email
                                print(f"[Allio MS] ✓ Email encontrado en token: {email}, username: {email_username}")
                            elif name:
                                import re
                                email_username = re.sub(r'[^a-zA-Z0-9_]', '', name)[:16]
                                print(f"[Allio MS] ✓ Nombre encontrado en token: {name}, username: {email_username}")
                            else:
                                print(f"[Allio MS] No se encontró email ni nombre en el token")
                        else:
                            print(f"[Allio MS] El access_token no parece ser un JWT válido (partes: {len(parts)})")
                    except Exception as token_err:
                        print(f"[Allio MS] Error decodificando token: {token_err}")

                # Xbox Live authentication
                headers = {"x-xbl-contract-version": "1"}
                payload = {
                    "RelyingParty": "http://auth.xboxlive.com",
                    "TokenType": "JWT",
                    "Properties": {
                        "AuthMethod": "RPS",
                        "SiteName": "user.auth.xboxlive.com",
                        "RpsTicket": f"d={access_token}",
                    },
                }
                user_resp = requests.post(XBOX_USER_AUTH_URL, json=payload, headers=headers, timeout=20)
                user_token = user_resp.json().get("Token")
                if not user_token:
                    print(f"[Allio] Error en autenticación Xbox: {user_resp.json()}")
                    return

                payload = {
                    "RelyingParty": "rp://api.minecraftservices.com/",
                    "TokenType": "JWT",
                    "Properties": {"UserTokens": [user_token], "SandboxId": "RETAIL"},
                }
                xsts_resp = requests.post(XBOX_XSTS_URL, json=payload, headers=headers, timeout=20)
                xsts_data = xsts_resp.json()
                if "DisplayClaims" not in xsts_data:
                    print(f"[Allio] Error en XSTS: {xsts_data}")
                    return

                display_claims = xsts_data.get("DisplayClaims", {})
                xui_list = display_claims.get("xui") if isinstance(display_claims, dict) else None
                xui = xui_list[0] if isinstance(xui_list, list) and xui_list else {}
                gamertag = xui.get("gtg") or xui.get("gt") or xui.get("gamerTag") or ""
                xuid = xui.get("xid") or xui.get("xuid") or ""
                userhash = xui.get("uhs") or ""
                
                # Intentar obtener más información del perfil de Xbox Live
                if userhash and xsts_data.get("Token"):
                    try:
                        xbl_token = xsts_data.get("Token")
                        profile_headers = {
                            "x-xbl-contract-version": "3",
                            "Authorization": f"XBL3.0 x={userhash};{xbl_token}",
                            "Accept-Language": "es-ES"
                        }
                        # Endpoint de perfil de Xbox Live
                        profile_url = "https://profile.xboxlive.com/users/me/profile/settings"
                        params = {"settings": "Gamertag,GameDisplayName,AccountTier,XboxOneRep,PreferredColor,RealName,Bio,Location"}
                        profile_resp = requests.get(profile_url, headers=profile_headers, params=params, timeout=10)
                        
                        if profile_resp.status_code == 200:
                            profile_data = profile_resp.json()
                            profile_users = profile_data.get("profileUsers", [])
                            if profile_users and len(profile_users) > 0:
                                settings = profile_users[0].get("settings", [])
                                for setting in settings:
                                    if setting.get("id") == "Gamertag" and not gamertag:
                                        gamertag = setting.get("value", "")
                                        print(f"[Allio Xbox] Gamertag obtenido del perfil: {gamertag}")
                                    elif setting.get("id") == "RealName" and not email_username:
                                        real_name = setting.get("value", "")
                                        if real_name:
                                            import re
                                            email_username = re.sub(r'[^a-zA-Z0-9_]', '', real_name)[:16]
                                            print(f"[Allio Xbox] Nombre real obtenido: {real_name} -> {email_username}")
                    except Exception as profile_err:
                        print(f"[Allio Xbox] No se pudo obtener perfil extendido: {profile_err}")
                
                # Si no hay gamertag ni XUID, usar el email como fallback temporal
                if not gamertag and not xuid:
                    gamertag = _ensure_username(email_username)
                    print(f"[Allio Xbox] Usando nombre temporal: {gamertag} (se preguntará después si es necesario)")
                
                # Si no hay gamertag (pero sí XUID), generar uno
                if not gamertag:
                    if xuid:
                        gamertag = f"Allio{xuid[:8]}"
                    else:
                        gamertag = _ensure_username(email_username)
                
                print(f"[Allio Xbox] Gamertag temporal: {gamertag} (XUID: {xuid if xuid else 'Sin Xbox Live'})")

                # Intentar autenticación adicional con Minecraft Java
                minecraft_username = gamertag  # Por defecto usar el gamertag de Xbox
                minecraft_token = None
                minecraft_uuid = ""
                minecraft_token_expires_at = None
                minecraft_java_owned = False
                
                try:
                    # Obtener token de Minecraft usando el token XSTS
                    xsts_token = xsts_data.get("Token")
                    minecraft_payload = {
                        "identityToken": f"XBL3.0 x={userhash};{xsts_token}"
                    }
                    
                    minecraft_resp = requests.post(MINECRAFT_LOGIN_URL, json=minecraft_payload, timeout=20)
                    if minecraft_resp.status_code == 200:
                        minecraft_data = minecraft_resp.json()
                        minecraft_token = minecraft_data.get("access_token")
                        # ¡FIX! No asumir True aquí, se verifica después
                        # minecraft_java_owned = True 
                        
                        if minecraft_token and minecraft_data.get("expires_in"):
                            try:
                                minecraft_token_expires_at = time.time() + float(minecraft_data.get("expires_in", 0))
                            except Exception:
                                minecraft_token_expires_at = None
                        
                        if minecraft_token:
                            # Obtener perfil de Minecraft Java
                            profile_headers = {"Authorization": f"Bearer {minecraft_token}"}
                            
                            # --- INICIO DEL BLOQUE CORREGIDO ---
                            profile_resp = requests.get(MINECRAFT_PROFILE_URL, headers=profile_headers, timeout=20)
                            
                            if profile_resp.status_code == 200:
                                profile_data = profile_resp.json()
                                minecraft_username = profile_data.get("name", gamertag)
                                minecraft_uuid = profile_data.get("id", "")
                                print(f"[Allio] OK Minecraft Java profile: {minecraft_username} ({minecraft_uuid})")
                                
                                # Usar el username de Minecraft Java como nombre principal
                                gamertag = minecraft_username
                                
                                # ADICIONAL: Verificar entitlements (permisos) para estar 100% seguros
                                try:
                                    ent_resp = requests.get(MINECRAFT_ENTITLEMENTS_URL, headers=profile_headers, timeout=15)
                                    if ent_resp.status_code == 200:
                                        entitlements = ent_resp.json().get('items', [])
                                        # Comprobar si 'product_minecraft' o 'game_minecraft' está en la lista de permisos
                                        if any(item.get('name') == 'product_minecraft' or item.get('name') == 'game_minecraft' for item in entitlements if isinstance(item, dict)):
                                            minecraft_java_owned = True
                                            print(f"[Allio] OK Verificada propiedad de Minecraft Java.")
                                        else:
                                            minecraft_java_owned = False
                                            print(f"[Allio] AVISO Usuario tiene perfil pero no propiedad de Minecraft Java.")
                                            minecraft_token = "0" # Forzar offline si no tiene propiedad
                                    else:
                                        print(f"[Allio] AVISO No se pudo verificar entitlements: {ent_resp.status_code}")
                                        # Asumir que sí lo tiene si el perfil existe (comportamiento anterior)
                                        minecraft_java_owned = True 
                                except Exception as ent_err:
                                    print(f"[Allio] Error verificando entitlements: {ent_err}")
                                    minecraft_java_owned = True # Asumir que sí si falla la comprobación

                            elif profile_resp.status_code == 404: # <--- ¡FIX AÑADIDO!
                                print(f"[Allio] AVISO Esta cuenta no tiene perfil de Minecraft Java (404).")
                                minecraft_java_owned = False
                                minecraft_token = "0" # Tratar como offline
                            else:
                                print(f"[Allio] AVISO No se pudo obtener perfil de Minecraft Java: {profile_resp.status_code}")
                                print(f"[Allio] Usando gamertag de Xbox: {gamertag}")
                                # No podemos estar seguros, pero el login_with_xbox funcionó.
                                # Lo más seguro es tratarlo como offline.
                                minecraft_java_owned = False
                                minecraft_token = "0"
                    elif minecraft_resp.status_code in [401, 403]:
                    # --- FIN DEL BLOQUE CORREGIDO ---
                        
                        print(f"[Allio] INFO Esta cuenta Microsoft no posee Minecraft Java Edition en esta cuenta Xbox")
                        minecraft_java_owned = False
                        
                        # INTENTAR obtener el perfil de Minecraft automáticamente
                        minecraft_username_from_email = None
                        
                        # 1. Buscar en launcher oficial de Minecraft PRIMERO
                        print(f"[Allio] 🔍 Buscando nombre y UUID en launcher oficial de Minecraft...")
                        try:
                            minecraft_dir = os.path.join(os.getenv('APPDATA', ''), '.minecraft')
                            launcher_accounts = os.path.join(minecraft_dir, 'launcher_accounts.json')
                            
                            if os.path.exists(launcher_accounts):
                                with open(launcher_accounts, 'r', encoding='utf-8') as f:
                                    accounts_data = json.load(f)
                                    
                                # Buscar cualquier cuenta con nombre válido
                                for account_id, account_info in accounts_data.get('accounts', {}).items():
                                    profile = account_info.get('minecraftProfile', {})
                                    account_name = profile.get('name', '')
                                    account_uuid = profile.get('id', '')
                                    
                                    if account_name and account_name != '':
                                        minecraft_username_from_email = account_name
                                        gamertag = account_name
                                        minecraft_username = account_name
                                        
                                        # Formatear UUID
                                        if account_uuid:
                                            uuid_hex = account_uuid.replace('-', '')
                                            if len(uuid_hex) == 32:
                                                minecraft_uuid = uuid_hex
                                                
                                        print(f"[Allio] ✅ PERFIL ENCONTRADO en launcher oficial:")
                                        print(f"[Allio]    Nombre: {minecraft_username_from_email}")
                                        print(f"[Allio]    UUID: {minecraft_uuid}")
                                        print(f"[Allio] ✅ Usando token MSAL con perfil oficial - MODO ONLINE")
                                        minecraft_java_owned = True  # Tiene Minecraft!
                                        
                                        break
                        except Exception as launcher_err:
                            print(f"[Allio] Error leyendo launcher oficial: {launcher_err}")
                        
                        # 2. Si no se encontró, intentar con el email
                        if not minecraft_username_from_email and ms_account_email:
                            print(f"[Allio] Intentando obtener perfil de Minecraft para: {ms_account_email}")
                            
                            try:
                                # Intentar obtener UUID desde el email/username
                                # Primero extraer el nombre antes del @
                                base_username = ms_account_email.split('@')[0]
                                print(f"[Allio] Buscando perfil para username base: {base_username}")
                                
                                # Intentar obtener UUID de Mojang
                                mojang_uuid_url = f"https://api.mojang.com/users/profiles/minecraft/{base_username}"
                                uuid_resp = requests.get(mojang_uuid_url, timeout=10)
                                
                                if uuid_resp.status_code == 200:
                                    uuid_data = uuid_resp.json()
                                    minecraft_username_from_email = uuid_data.get("name")
                                    minecraft_uuid = uuid_data.get("id", "")
                                    print(f"[Allio] ✅ PERFIL ENCONTRADO en Mojang: {minecraft_username_from_email} (UUID: {minecraft_uuid})")
                                    gamertag = minecraft_username_from_email
                                    minecraft_username = minecraft_username_from_email
                                else:
                                    print(f"[Allio] No se encontró perfil de Mojang para: {base_username} (HTTP {uuid_resp.status_code})")
                                    
                            except Exception as mojang_err:
                                print(f"[Allio] Error buscando en Mojang: {mojang_err}")
                        
                        # Si no se encontró en Mojang, PREGUNTAR AL USUARIO
                        if not minecraft_username_from_email and not xuid:
                            print(f"[Allio] No se encontró perfil automáticamente, preguntando al usuario...")
                            
                            # Primero intentar leer desde archivo como último recurso
                            nombre_archivo = os.path.join(os.path.dirname(__file__), "MI_NOMBRE_MINECRAFT.txt")
                            nombre_custom = None
                            
                            try:
                                if os.path.exists(nombre_archivo):
                                    with open(nombre_archivo, 'r', encoding='utf-8') as f:
                                        primera_linea = f.readline().strip()
                                        if primera_linea and primera_linea != "sigridsauco2013":
                                            import re
                                            clean_name = re.sub(r'[^a-zA-Z0-9_]', '', primera_linea)[:16]
                                            if len(clean_name) >= 3:
                                                nombre_custom = clean_name
                                                print(f"[Allio] ✅ Nombre leído desde archivo: '{nombre_custom}'")
                            except Exception as e:
                                print(f"[Allio] Error leyendo archivo: {e}")
                            
                            # Si no hay nombre en archivo, usar Player temporalmente
                            # (se preguntará al usuario al final del flujo de login)
                            
                            if nombre_custom:
                                gamertag = nombre_custom
                                minecraft_username = nombre_custom
                                print(f"[Allio] ✅ Usando nombre de usuario: '{gamertag}'")
                            else:
                                gamertag = _default_username_from_seed(email_username if 'email_username' in locals() else None)
                                minecraft_username = gamertag
                                print(f"[Allio] ⚠️ Usando nombre por defecto: '{gamertag}'")
                        
                        print(f"[Allio] INFO Sesión offline para: {gamertag}")
                        
                        # Generar UUID offline si no se obtuvo de Mojang
                        if not minecraft_uuid:
                            safe_gamertag = _ensure_username(gamertag)
                            offline_uuid = uuid.uuid3(uuid.NAMESPACE_DNS, f"OfflinePlayer:{safe_gamertag}")
                            minecraft_uuid = offline_uuid.hex
                        
                        minecraft_username = gamertag
                        minecraft_token = "0"  # Token offline
                    else:
                        print(f"[Allio] AVISO Error de autenticación Minecraft Java: {minecraft_resp.status_code}")
                        print(f"[Allio] Se usará modo offline con gamertag: {gamertag}")
                        minecraft_java_owned = False
                        # Generar UUID offline consistente
                        safe_gamertag = _ensure_username(gamertag)
                        offline_uuid = uuid.uuid3(uuid.NAMESPACE_DNS, f"OfflinePlayer:{safe_gamertag}")
                        minecraft_uuid = offline_uuid.hex
                        minecraft_username = safe_gamertag
                        minecraft_token = "0"  # Token offline
                except Exception as e:
                    print(f"[Allio] Error en autenticación Minecraft Java: {e}")
                    print(f"[Allio] Se usará modo offline con gamertag: {gamertag}")
                    minecraft_java_owned = False
                    # Generar UUID offline consistente
                    safe_gamertag = _ensure_username(gamertag)
                    offline_uuid = uuid.uuid3(uuid.NAMESPACE_DNS, f"OfflinePlayer:{safe_gamertag}")
                    minecraft_uuid = offline_uuid.hex
                    minecraft_username = safe_gamertag
                    minecraft_token = "0"  # Token offline

                # Si tenemos un username de Minecraft Java configurado, usarlo como nombre principal
                final_username = gamertag
                try:
                    config_file = "allio_config.json"
                    if os.path.exists(config_file):
                        with open(config_file, 'r', encoding='utf-8') as f:
                            config = json.load(f)
                            minecraft_java_username = config.get('minecraft_java_username', '')
                            if minecraft_java_username:
                                final_username = minecraft_java_username
                                print(f"[Allio] OK Usando username de Minecraft Java como principal: {final_username}")
                except Exception as e:
                    print(f"[Allio] Error leyendo config para username: {e}")
                
                # ÚLTIMO RECURSO: Si no se pudo detectar un username válido, generar uno seguro
                if not final_username or final_username.strip() == "":
                    final_username = _default_username_from_seed(None)
                    minecraft_username = final_username
                    gamertag = final_username
                    print(f"[Allio] Username no detectado. Se generó '{final_username}' como fallback seguro.")

                print(f"[Allio] Login finalizado: {final_username} / {xuid}")

                # Usar el email que ya obtuvimos de Microsoft Graph API
                account_email = ms_account_email or ""

                try:
                    session_payload = {
                        'gamertag': final_username,
                        'profile_name': final_username,
                        'minecraft_username': minecraft_username,
                        'xuid': xuid,
                        'user_token': user_token,
                        'xsts_token': xsts_data.get('Token'),
                        'ms_access_token': tokens.get('access_token'),
                        'ms_refresh_token': tokens.get('refresh_token'),
                        'ms_token_expires_at': (time.time() + float(tokens.get('expires_in', 0))) if tokens.get('expires_in') else None,
                        'minecraft_token': minecraft_token,
                        'minecraft_token_expires_at': minecraft_token_expires_at,
                        'ms_account_email': account_email,
                        'xbox_userhash': userhash,
                        'minecraft_java_entitled': minecraft_java_owned,
                        'auth_source': 'online' if minecraft_java_owned else 'offline',
                    }
                    if minecraft_uuid:
                        # Formatear UUID correctamente
                        if len(minecraft_uuid) == 32 and '-' not in minecraft_uuid:
                            # Es un UUID sin guiones, formatearlo
                            formatted_uuid = f"{minecraft_uuid[0:8]}-{minecraft_uuid[8:12]}-{minecraft_uuid[12:16]}-{minecraft_uuid[16:20]}-{minecraft_uuid[20:32]}"
                            session_payload['minecraft_uuid'] = formatted_uuid
                            session_payload['minecraft_uuid_nodash'] = minecraft_uuid
                        else:
                            # Ya tiene formato de UUID o es diferente
                            session_payload['minecraft_uuid'] = minecraft_uuid
                            session_payload['minecraft_uuid_nodash'] = minecraft_uuid.replace('-', '')
                            
                    if mw is not None and hasattr(mw, 'update_auth_session'):
                        mw.update_auth_session(session_payload)
                        print(f"[Allio] Sesión de autenticación actualizada para {final_username} ({'online' if minecraft_java_owned else 'offline'})")
                        
                        # GUARDAR TOKEN OAUTH PARA AUTO-LOGIN FUTURO (compatibilidad con MSAL silent auth)
                        if tokens.get('access_token') and not tokens.get('_msal_user_email'):
                            # Solo si vino de OAuth tradicional (no de MSAL)
                            try:
                                print("[Allio] Guardando token OAuth para auto-login...")
                                oauth_cache_file = os.path.join(os.getenv('APPDATA', ''), 'AllioClient', 'oauth_token_cache.json')
                                os.makedirs(os.path.dirname(oauth_cache_file), exist_ok=True)
                                
                                oauth_cache_data = {
                                    "access_token": tokens.get('access_token'),
                                    "refresh_token": tokens.get('refresh_token', ''),
                                    "expires_at": time.time() + float(tokens.get('expires_in', 3600)),
                                    "scope": MS_OAUTH_SCOPE,
                                    "username": ms_account_email or final_username,
                                    "saved_at": time.time()
                                }
                                
                                with open(oauth_cache_file, 'w') as f:
                                    json.dump(oauth_cache_data, f, indent=2)
                                
                                print("[Allio] ✅ Token guardado - la próxima vez iniciará sesión automáticamente")
                                
                            except Exception as cache_err:
                                print(f"[Allio] Advertencia: No se pudo guardar token OAuth: {cache_err}")
                        
                        # Actualizar _username y _memory_config con el gamertag/username
                        if hasattr(mw, '_username'):
                            mw._username = final_username
                        if hasattr(mw, '_memory_config') and isinstance(mw._memory_config, dict):
                            mw._memory_config['gamertag'] = final_username
                            if minecraft_username:
                                mw._memory_config['minecraft_java_username'] = minecraft_username
                        
                        if hasattr(mw, 'save_config'):
                            try:
                                mw.save_config()
                            except Exception as save_err:
                                print(f"[Allio] Advertencia guardando configuración tras login: {save_err}")
                        try:
                            restored = mw.get_auth_session() if hasattr(mw, 'get_auth_session') else {}
                            print(f"[Allio] Sesión en memoria tras login: claves={sorted(restored.keys()) if isinstance(restored, dict) else restored}")
                        except Exception:
                            pass
                except Exception as e:
                    print(f"[Allio] Error actualizando sesión de autenticación: {e}")
                
                # Mostrar advertencia si no tiene Xbox Live
                if not xuid:
                    try:
                        from PyQt6.QtWidgets import QMessageBox
                        from PyQt6.QtCore import QTimer
                        def _show_xbox_warning():
                            try:
                                QMessageBox.information(
                                    mw if mw else None,
                                    "Xbox Live no configurado",
                                    f"Tu cuenta de Microsoft no tiene Xbox Live configurado.\n\n"
                                    f"Estás usando el nombre: {final_username}\n\n"
                                    f"Para usar tu propio Gamertag y avatar:\n"
                                    f"1. Visita https://www.xbox.com\n"
                                    f"2. Crea tu perfil de Xbox (es GRATIS)\n"
                                    f"3. Vuelve a iniciar sesión en el launcher\n\n"
                                    f"Mientras tanto, puedes jugar normalmente en modo offline."
                                )
                            except Exception:
                                pass
                        QTimer.singleShot(500, _show_xbox_warning)
                    except Exception:
                        pass

                try:
                    mw = parent if parent is not None else self.window()
                    if mw is not None:
                        try:
                            if mw is not None:
                                try:
                                    setattr(mw, '_open_instances_on_success', True)
                                    print(f"[Allio] parent flag _open_instances_on_success set True for '{final_username}'")
                                except Exception:
                                    pass

                            try:
                                self.showLoadingRequested.emit(final_username)
                                print(f"[Allio] showLoadingRequested.emit done for '{final_username}'")
                            except Exception as e:
                                print(f"[Allio] showLoadingRequested.emit failed: {e}")

                            try:
                                from PyQt6.QtCore import QTimer as _QTimer
                                if hasattr(mw, 'show_loading_with') and final_username:
                                    _QTimer.singleShot(0, lambda g=final_username, _mw=mw: _mw.show_loading_with(g))
                                    print(f"[Allio] QTimer.singleShot scheduled parent.show_loading_with for '{final_username}'")
                            except Exception as e:
                                print(f"[Allio] QTimer scheduling fallback failed: {e}")
                                if hasattr(mw, 'show_loading_with') and final_username:
                                    try:
                                        mw.show_loading_with(final_username)
                                    except Exception:
                                        pass
                        except Exception:
                            if hasattr(mw, 'show_loading_with') and final_username:
                                try:
                                    mw.show_loading_with(final_username)
                                except Exception:
                                    pass

                        if hasattr(mw, 'set_profile_avatar'):
                            try:
                                mw.fetch_and_set_avatar(final_username)
                            except Exception:
                                pass
                except Exception as e:
                    print(f"[Allio] Error aplicando resultado al UI: {e}")
            except Exception as e:
                print(f"[Allio] Error en flujo de login: {e}")
            finally:
                try:
                    self._login_in_progress = False
                except Exception:
                    pass
                try:
                    self.xbox_button.setEnabled(True)
                except Exception:
                    pass
                print('[Allio] Login flow finalized, _login_in_progress cleared')
        
        def _on_xbox_clicked():
            try:
                threading.Thread(target=_login_flow_in_thread, daemon=True).start()
            except Exception as e:
                print(f"[BlackLogoWidget] Error al iniciar flujo de login: {e}")

        try:
            self .xbox_button .clicked .connect (_on_xbox_clicked )
        except Exception :
            pass

    def resizeEvent (self ,e ):
        try :
            w =max (1 ,self .width ())
            h =max (1 ,self .height ())
            base_w ,base_h =1100.0 ,620.0 
            scale =min (w /base_w ,h /base_h )
            scale =max (0.8 ,min (1.25 ,scale ))

            try :
                top_fs =int (36 *scale )
                bottom_fs =int (28 *scale )
                self .title_top .setStyleSheet (f"color: white; font: 800 {top_fs}px 'Segoe UI';")
                self .title_bottom .setStyleSheet (f"color: white; font: 800 {bottom_fs}px 'Segoe UI';")
            except Exception :
                pass 

            try :
                btn_fs =int (16 *scale )
                pad_v =max (6 ,int (8 *scale ))
                pad_h =max (8 ,int (12 *scale ))
                self .xbox_button .setStyleSheet (f"background:#cd1955; color:white; font:600 {btn_fs}px 'Segoe UI'; padding:{pad_v}px {pad_h}px; border-radius:8px;")
                icon_sz =max (18 ,int (26 *scale ))
                self .xbox_button .setIconSize (QSize (icon_sz ,icon_sz ))
                try :
                    self .xbox_button .setMaximumWidth (420 )
                except Exception :
                    pass 
            except Exception :
                pass 
        except Exception :
            pass 
        try :
            super ().resizeEvent (e )
        except Exception :
            pass 

    def set_gamertag (self ,gamertag :str ):
        try :
            val =(gamertag .strip ()or None )
        except Exception :
            val =None 
        self ._auto_gamertag =val 

        try :
            parent =self .parent ()if self .parent ()is not None else self .window ()
            if parent is not None :
                if val is not None and hasattr (parent ,"_username"):
                    try :
                        parent ._username =val 
                    except Exception :
                        pass 

                if val is not None :
                    try :
                        try:
                            from PyQt6.QtCore import QTimer as _QTimer
                            if hasattr (parent ,"show_loading_with"):
                                print (f"[BlackLogoWidget] Propagando gamertag '{val}' programando show_loading_with en hilo GUI")
                                _QTimer.singleShot(0, lambda v=val, p=parent: p.show_loading_with(v))
                            elif hasattr (parent ,"fetch_and_set_avatar"):
                                print (f"[BlackLogoWidget] Propagando gamertag '{val}' usando fetch_and_set_avatar (fallback)")
                                parent .fetch_and_set_avatar (val )
                        except Exception:
                            if hasattr (parent ,"show_loading_with"):
                                try:
                                    parent .show_loading_with (val )
                                except Exception:
                                    pass
                            elif hasattr (parent ,"fetch_and_set_avatar"):
                                try:
                                    parent .fetch_and_set_avatar (val )
                                except Exception:
                                    pass
                    except Exception as e :
                        print (f"[BlackLogoWidget] Error propagando gamertag al parent: {e}")

                if hasattr (parent ,"save_config"):
                    try :
                        parent .save_config ()
                    except Exception :
                        pass 
        except Exception as e :
            print (f"[BlackLogoWidget] Error propagar gamertag al parent: {e}")

    def paintEvent (self ,event ):
        p =QPainter (self )
        p .setRenderHint (QPainter .RenderHint .Antialiasing )
        if self .bg :
            scaled =self .bg .scaled (self .size (),Qt .AspectRatioMode .KeepAspectRatioByExpanding ,Qt .TransformationMode .SmoothTransformation )
            x =(self .width ()-scaled .width ())//2 
            y =(self .height ()-scaled .height ())//2 
            p .drawPixmap (x ,y ,scaled )
        else :
            p .fillRect (self .rect (),QColor (0 ,0 ,0 ))
        super ().paintEvent (event )

class TitleBar (QWidget ):

    minimizeRequested =pyqtSignal ()
    maximizeRequested =pyqtSignal ()
    closeRequested =pyqtSignal ()

    def __init__ (self ,parent =None ):
        super ().__init__ (parent )
        self .setObjectName ("titleBar")
        self .setFixedHeight (36 )
        lay =QHBoxLayout (self )
        lay .setContentsMargins (10 ,0 ,10 ,0 )
        lay .setSpacing (0 )
        self .leftPad =QWidget ()

        self .leftPad .setFixedWidth (6 )


        self .icon_label =QLabel ()
        self .icon_label .setObjectName ("titleIcon")
        self .icon_label .setFixedSize (28 ,28 )
        self .icon_label .setAlignment (Qt .AlignmentFlag .AlignCenter )
        icon_path =resource_path ("icono.png")
        if os .path .exists (icon_path ):
            pm =QPixmap (icon_path )
            size =28 
            round_pm =QPixmap (size ,size )
            round_pm .fill (Qt .GlobalColor .transparent )
            painter =QPainter (round_pm )
            painter .setRenderHint (QPainter .RenderHint .Antialiasing )
            path =QPainterPath ()
            path .addEllipse (0 ,0 ,size ,size )
            painter .setClipPath (path )
            scaled =pm .scaled (size ,size ,Qt .AspectRatioMode .KeepAspectRatioByExpanding ,
            Qt .TransformationMode .SmoothTransformation )
            dx =(scaled .width ()-size )//2 
            dy =(scaled .height ()-size )//2 
            painter .drawPixmap (-dx ,-dy ,scaled )
            painter .end ()
            self .icon_label .setPixmap (round_pm )

        self .label =QLabel (APP_TITLE )
        self .label .setObjectName ("titleLabel")

        self .label .setAlignment (Qt .AlignmentFlag .AlignVCenter |Qt .AlignmentFlag .AlignLeft )
        try :
            self .label .setStyleSheet ("color:#f2f2f2; font:600 14px 'Avenir, Segoe UI';")
        except Exception :
            pass 
        btnWrap =QWidget ()
        hb =QHBoxLayout (btnWrap )
        hb .setContentsMargins (0 ,0 ,0 ,0 )
        hb .setSpacing (1 )


        self .btn_min =QPushButton ()
        self .btn_min .setObjectName ("titleBtn")
        self .btn_max =QPushButton ()
        self .btn_max .setObjectName ("titleBtn")
        self .btn_close =QPushButton ()
        self .btn_close .setObjectName ("closeBtn")

        for b in (self .btn_min ,self .btn_max ,self .btn_close ):
            b .setCursor (Qt .CursorShape .PointingHandCursor )
            b .setFixedSize (36 ,28 )
            b .setFlat (True )
            b .setStyleSheet ("border: none; background: none;")
            hb .addWidget (b ,0 ,Qt .AlignmentFlag .AlignVCenter )


        try :
            style =self .style ()if hasattr (self ,'style')else QApplication .style ()
            icon_min =style .standardIcon (QStyle .StandardPixmap .SP_TitleBarMinButton )
            icon_max =style .standardIcon (QStyle .StandardPixmap .SP_TitleBarMaxButton )
            icon_close =style .standardIcon (QStyle .StandardPixmap .SP_TitleBarCloseButton )
            self .btn_min .setIcon (icon_min )
            self .btn_min .setIconSize (QSize (14 ,14 ))
            self .btn_max .setIcon (icon_max )
            self .btn_max .setIconSize (QSize (14 ,14 ))
            self .btn_close .setIcon (icon_close )
            self .btn_close .setIconSize (QSize (14 ,14 ))
        except Exception :

            try :
                self .btn_min .setIcon (QIcon (resource_path ("minimizar.png")))
                self .btn_max .setIcon (QIcon (resource_path ("maximizar.png")))
                self .btn_close .setIcon (QIcon (resource_path ("cerrar.png")))
            except Exception :
                pass 


        self .btn_min .clicked .connect (lambda :self .minimizeRequested .emit ())
        self .btn_close .clicked .connect (lambda :self .closeRequested .emit ())
        self .btn_max .clicked .connect (lambda :self .maximizeRequested .emit ())

        lay .addWidget (self .icon_label ,0 )
        lay .addWidget (self .leftPad ,0 )
        lay .addWidget (self .label ,1 )
        lay .addWidget (btnWrap ,0 ,Qt .AlignmentFlag .AlignRight |Qt .AlignmentFlag .AlignVCenter )


        try :
            self .leftPad .setFixedWidth (6 )
        except Exception :
            pass 

        self ._drag_pos =None 
        self ._btnWrap =btnWrap 

    def paintEvent (self ,e ):
        p =QPainter (self )
        p .setRenderHint (QPainter .RenderHint .Antialiasing )

        try :
            color =QColor ("#0b0a0a")
        except Exception :
            color =QColor (20 ,19 ,19 )
        p .fillRect (self .rect (),color )
        super ().paintEvent (e )

    def resizeEvent (self ,e ):

        try :
            self .leftPad .setFixedWidth (6 )
        except Exception :
            pass 
        super ().resizeEvent (e )

    def mouseDoubleClickEvent (self ,e ):
        if e .button ()==Qt .MouseButton .LeftButton :

            self .maximizeRequested .emit ()

    def mousePressEvent (self ,e ):
        if e .button ()==Qt .MouseButton .LeftButton :
            self ._drag_pos =e .globalPosition ()

    def mouseMoveEvent (self ,e ):
        if self ._drag_pos :
            delta =e .globalPosition ()-self ._drag_pos 
            self .window ().move (self .window ().x ()+int (delta .x ()),self .window ().y ()+int (delta .y ()))
            self ._drag_pos =e .globalPosition ()

    def mouseReleaseEvent (self ,e ):
        self ._drag_pos =None 

# ============================================================
# Discord Rich Presence Manager
# ============================================================
class DiscordRPC:
    """Gestiona la conexión y actualización del Discord Rich Presence"""
    
    def __init__(self, client_id: str = "1234567890123456789"):
        """
        Inicializa el Discord RPC
        
        Args:
            client_id: El Client ID de la aplicación de Discord
                      (puedes crear una en https://discord.com/developers/applications)
        """
        self.client_id = client_id
        self.rpc = None
        self.connected = False
        self.start_time = int(time.time())
        
    def connect(self):
        """Intenta conectar con Discord"""
        if Presence is None:
            print("[Discord RPC] pypresence no está disponible")
            return False
            
        try:
            self.rpc = Presence(self.client_id)
            self.rpc.connect()
            self.connected = True
            print("[Discord RPC] Conectado exitosamente")
            return True
        except Exception as e:
            print(f"[Discord RPC] Error al conectar: {e}")
            self.connected = False
            return False
    
    def disconnect(self):
        """Desconecta del Discord RPC"""
        if self.rpc and self.connected:
            try:
                self.rpc.close()
                self.connected = False
                print("[Discord RPC] Desconectado")
            except Exception as e:
                print(f"[Discord RPC] Error al desconectar: {e}")
    
    def update_presence(self, 
                       state: str = None,
                       details: str = None, 
                       large_image: str = "allio_logo",
                       large_text: str = "Allio Client",
                       small_image: str = None,
                       small_text: str = None,
                       start_timestamp: int = None,
                       buttons: list = None):
        """
        Actualiza el Rich Presence en Discord
        
        Args:
            state: Texto que aparece debajo del details
            details: Texto principal que aparece en la presencia
            large_image: Clave de la imagen grande (debe estar subida en Discord Dev Portal)
            large_text: Texto al pasar el mouse sobre la imagen grande
            small_image: Clave de la imagen pequeña
            small_text: Texto al pasar el mouse sobre la imagen pequeña
            start_timestamp: Timestamp de inicio (para mostrar "Elapsed")
            buttons: Lista de botones [{"label": "texto", "url": "https://..."}]
        """
        if not self.connected or not self.rpc:
            return False
            
        try:
            kwargs = {}
            
            if state is not None:
                kwargs['state'] = state
            if details is not None:
                kwargs['details'] = details
            if large_image is not None:
                kwargs['large_image'] = large_image
            if large_text is not None:
                kwargs['large_text'] = large_text
            if small_image is not None:
                kwargs['small_image'] = small_image
            if small_text is not None:
                kwargs['small_text'] = small_text
            if start_timestamp is not None:
                kwargs['start'] = start_timestamp
            if buttons is not None:
                kwargs['buttons'] = buttons
            
            # Debug: mostrar qué se está enviando
            print(f"[Discord RPC] Actualizando presencia: {kwargs}")
                
            self.rpc.update(**kwargs)
            return True
        except Exception as e:
            print(f"[Discord RPC] Error actualizando presencia: {e}")
            return False
    
    def set_idle(self, username: str = None):
        """Establece el estado como 'En el launcher'"""
        details = "En el launcher"
        if username:
            state = f"Jugador: {username}"
        else:
            state = "Navegando por el menú"
        
        self.update_presence(
            details=details,
            state=state,
            large_image="logo_grande",
            large_text="PermadeatH",
            start_timestamp=self.start_time
        )
    
    def set_playing(self, instance_name: str = "Minecraft", username: str = None):
        """Establece el estado como 'Jugando'"""
        details = f"Jugando {instance_name}"
        if username:
            state = f"Como {username}"
        else:
            state = "En partida"
        
        self.update_presence(
            details=details,
            state=state,
            large_image="logo_grande",
            large_text="PermadeatH",
            small_image="logo_peque",
            small_text="Allio Client",
            start_timestamp=int(time.time())  # Nuevo timestamp para esta sesión de juego
        )
    
    def set_downloading(self, what: str = "archivos"):
        """Establece el estado como 'Descargando'"""
        self.update_presence(
            details=f"Descargando {what}",
            state="Preparando el juego...",
            large_image="logo_grande",
            large_text="PermadeatH",
            start_timestamp=self.start_time
        )

class LauncherWindow (QWidget ):
    avatarReady =pyqtSignal (QPixmap )
    avatarStatus =pyqtSignal (str ,bool )

    def __init__ (self ):
        super ().__init__ ()
        self .setWindowTitle (APP_TITLE )
        icon_path =resource_path ("icono.png")
        
        # Configuración en memoria para ejecutables (SIN valores por defecto de usuario)
        self._memory_config = {
            'gamertag': '',
            'minecraft_java_username': '',  # NO poner valor por defecto
            'instances': {},
            'custom_client': '',
            'server': '',
            'version': APP_TITLE,
            'last_updated': '',
            'client_token': ''
        }
        self._auth_session = {}
        self._client_token = ''
        self._is_executable = is_running_as_executable()
        self._auto_login = False  # Flag para controlar el auto-login
        self._is_startup = True   # Flag para indicar que estamos en el proceso de inicio
        self._profile_image = None  # Para almacenar la imagen del perfil
        
        # Inicializar Discord Rich Presence
        self.discord_rpc = DiscordRPC(client_id="1234567890123456789")  # Cambiar por tu Client ID
        # Conectar en un hilo separado para no bloquear la UI
        threading.Thread(target=self._init_discord_rpc, daemon=True).start()
        
        # Conectar nuestro propio handler para avatarReady
        self.avatarReady.connect(self._on_main_avatar_ready)
        
        if os .path .exists (icon_path ):
            self .setWindowIcon (QIcon (icon_path ))
        if globals().get('USE_NATIVE_TITLEBAR', False):
            # Use normal window decorations
            try:
                self.setWindowFlags(Qt.WindowType.Window)
            except Exception:
                pass
            # try to enable dark titlebar on supported Windows versions
            try:
                if ctypes is not None and sys.platform.startswith('win'):
                    def set_windows_dark_titlebar(hwnd, enable=True):
                        # DWMWA_USE_IMMERSIVE_DARK_MODE may be 19 or 20 depending on Windows build
                        DWMWA_USE_IMMERSIVE_DARK_MODE_1 = 19
                        DWMWA_USE_IMMERSIVE_DARK_MODE_2 = 20
                        try:
                            val = wintypes.BOOL(1 if enable else 0)
                            hwnd_t = wintypes.HWND(int(hwnd))
                            # try new attr
                            try:
                                ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd_t, DWMWA_USE_IMMERSIVE_DARK_MODE_2, ctypes.byref(val), ctypes.sizeof(val))
                                return True
                            except Exception:
                                pass
                            try:
                                ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd_t, DWMWA_USE_IMMERSIVE_DARK_MODE_1, ctypes.byref(val), ctypes.sizeof(val))
                                return True
                            except Exception:
                                return False
                        except Exception:
                            return False

                    try:
                        # call with the window handle (winId())
                        set_windows_dark_titlebar(self.winId(), True)
                    except Exception:
                        pass
            except Exception:
                pass
        else:
            try:
                self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
            except Exception:
                pass
            try:
                self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
            except Exception:
                pass

        self .mainBg =BlackLogoWidget (self )
        main_layout =QVBoxLayout (self .mainBg )
        main_layout .setContentsMargins (0 ,0 ,0 ,0 )
        main_layout .setSpacing (0 )

        outer =QVBoxLayout (self )

        outer .setContentsMargins (0 ,0 ,0 ,0 )
        # mainBg should fill available space when visible
        outer .addWidget (self .mainBg ,1 )


        self .loadingWidget =LoadingWidget (self )
        outer .addWidget (self .loadingWidget ,0 )
        self .loadingWidget .hide ()

        self .loadingWidget .checkFinished .connect (self ._on_loading_finished )

        self .mapWidget =MapWidget (self )
        # make the mapWidget fill available space when shown
        outer .addWidget (self .mapWidget ,1 )
        self .mapWidget .hide ()


        # DESHABILITADO: UnauthorizedWidget
        # try :
        #     self .unauthorized_widget =UnauthorizedWidget (self )
        #     outer .addWidget (self .unauthorized_widget ,0 )
        #     self .unauthorized_widget .hide ()
        # except Exception :
        #     self .unauthorized_widget =None 
        self .unauthorized_widget = None


        self .instancesWidget =InstancesWidget (self )
        # treat instancesWidget as an overlay child (do not add to the main layout)
        try:
            self.instancesWidget.setParent(self)
        except Exception:
            pass
        self .instancesWidget .hide ()


        try :

            self .notification =NotificationWidget (self .mapWidget )

            try :

                if hasattr (self ,'mapWidget')and self .mapWidget is not None :
                    try:
                        tb_height = _computed_titlebar_height(self.mapWidget)
                    except Exception:
                        tb_height = 44
                    nx =max (0 ,self .mapWidget .width ()-self .notification .width ()-NOTIF_RIGHT_MARGIN )
                    ny =tb_height +8 

                    self .notification .move (nx ,ny )
                    self .notification .raise_ ()
                else :

                    nx =max (8 ,self .width ()-self .notification .width ()-8 )
                    ny =44 
                    self .notification .setParent (self )
                    self .notification .move (nx ,ny )
                self .notification .hide ()
            except Exception :
                pass 
        except Exception :
            self .notification =None 


        self .resize (1280 ,748 )
        try :
            self .setMinimumSize (800 ,600 )
        except Exception :
            pass 
        self .apply_style ()
        self ._normal_geometry =None 
        self .update_mask ()


        self .load_config ()
        
        # Si hay auto_login configurado, ocultar la pantalla principal inmediatamente y abrir directamente la ventana de instancias
        if hasattr(self, '_auto_login') and self._auto_login:
            # Ocultar la pantalla principal de inicio inmediatamente
            if hasattr(self, 'mainBg'):
                self.mainBg.hide()
            # Iniciar el proceso de auto-login sin retraso
            QTimer.singleShot(10, self._perform_auto_login)

        # Intento automático de reparación de assets de sonido si faltan (se ejecuta en hilo separado)
        try:
            def _start_assets_repair_thread():
                try:
                    self._attempt_auto_repair_assets()
                except Exception as e:
                    print(f"[Allio] Error en thread de reparación automática: {e}")

            threading.Thread(target=_start_assets_repair_thread, daemon=True).start()
        except Exception as e:
            print(f"[Allio] No se pudo iniciar hilo de reparación automática: {e}")



    def resizeEvent (self ,e ):

        try :
            if hasattr (self ,'notification')and self .notification is not None :

                if hasattr (self ,'mapWidget')and self .notification .parent ()!=self .mapWidget :
                    try :
                        self .notification .setParent (self .mapWidget )
                    except Exception :
                        pass 


                try :
                    try:
                        tb_height = _computed_titlebar_height(self.mapWidget)
                    except Exception:
                        tb_height = 44
                except Exception :
                    tb_height =44 
                self .notification .adjustSize ()
                nx =max (0 ,self .mapWidget .width ()-self .notification .width ()-NOTIF_RIGHT_MARGIN )
                ny =tb_height +8 
                self .notification .move (nx ,ny )
                self .notification .raise_ ()
        except Exception as e :
            print (f"Error posicionando notificación: {e}")

        super ().resizeEvent (e )

    def load_config (self ):
        """Carga la configuración guardada del archivo JSON, archivo temporal o usa valores por defecto en memoria para ejecutables"""
        try :
            # Si es ejecutable, intentar cargar desde archivo temporal o usar configuración en memoria
            if self._is_executable:
                print("[Allio Config] Ejecutándose como .exe - buscando configuración guardada")
                
                # Intentar cargar desde el archivo temporal en AppData
                temp_config_loaded = False
                auto_login = False
                try:
                    temp_dir = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'AllioClient')
                    temp_config = os.path.join(temp_dir, 'temp_config.json')
                    
                    if os.path.exists(temp_config):
                        with open(temp_config, 'r', encoding='utf-8') as f:
                            saved_config = json.load(f)
                            if isinstance(saved_config, dict):
                                self._memory_config.update(saved_config)
                                if not self._client_token:
                                    self._client_token = self._memory_config.get('client_token', '') or ''
                                stored_session = saved_config.get('auth_session') if isinstance(saved_config, dict) else None
                                if isinstance(stored_session, dict) and stored_session:
                                    try:
                                        self.update_auth_session(stored_session)
                                    except Exception as sess_err:
                                        print(f"[Allio Config] Error restaurando auth_session: {sess_err}")
                                else:
                                    self._auth_session = {}
                                temp_config_loaded = True
                                print(f"[Allio Config] Configuración cargada de {temp_config}")
                                
                                # Si hay un usuario guardado, restaurarlo y configurar auto-login
                                if self._memory_config.get('gamertag'):
                                    print(f"[Allio Config] Sesión restaurada para: {self._memory_config.get('gamertag')}")
                                    auto_login = True
                except Exception as e:
                    print(f"[Allio Config] Error cargando configuración temporal: {e}")
                
                # Usar la configuración cargada o valores vacíos (NO valores por defecto)
                saved_gamertag = self._memory_config.get('gamertag', '')
                minecraft_java_username = self._memory_config.get('minecraft_java_username', '')
                
                # Priorizar el username de Minecraft Java si está disponible
                if minecraft_java_username and minecraft_java_username != '':
                    self._username = minecraft_java_username
                    print(f"[Allio Config] Usando username de Minecraft Java: {minecraft_java_username}")
                elif saved_gamertag and saved_gamertag != '':
                    self._username = saved_gamertag
                    print(f"[Allio Config] Usando gamertag de Xbox: {saved_gamertag}")
                else:
                    self._username = "Sin sesión"
                    print("[Allio Config] No hay sesión guardada - usuario debe hacer login")
                    print(f"[Allio Config] Usando gamertag de Xbox: {saved_gamertag}")
                    # Intentar usar un nametag local como fallback cuando no hay sesión
                    try:
                        from nametag_manager import get_nametag
                        _local_nt = get_nametag()
                        if _local_nt:
                            # Usar el nametag local como username visible
                            self._username = _local_nt
                            self._used_local_nametag = True
                            print(f"[Allio Config] Usando nametag local como fallback: {_local_nt}")
                            # Actualizar botón de perfil si existe
                            if hasattr(self, 'btn_profile'):
                                short = _local_nt if len(_local_nt) <= 12 else _local_nt[:11] + "…"
                                try:
                                    self.btn_profile.setText(short)
                                    self.btn_profile.setToolTip(f"Local nametag: {_local_nt}")
                                except Exception:
                                    pass
                    except Exception as _nt_e:
                        print(f"[Allio Config] Error leyendo nametag local: {_nt_e}")
                    
                self._custom_client = self._memory_config.get('custom_client', '')
                self._server = self._memory_config.get('server', '')
                self._minecraft_java_username = minecraft_java_username
                if not self._client_token:
                    try:
                        self._client_token = self._memory_config.get('client_token', '') or ''
                    except Exception:
                        self._client_token = ''
                
                # Configurar auto-login si se restauró una sesión
                if auto_login and self._username:
                    self._auto_login = True
                    
                    # Actualizar botón de perfil si ya existe
                    if hasattr(self, 'btn_profile'):
                        short = self._username if len(self._username) <= 12 else self._username[:11] + "…"
                        self.btn_profile.setText(short)
                        self.btn_profile.setToolTip(f"Xbox: {self._username}")
                    
                    print(f"[Allio Config] Auto-login configurado para: {self._username}")
                else:
                    self._auto_login = False
                
                # ===== DESHABILITADO: Carga de nametags.json =====
                # Ya no se verifica autorización desde nametags.json
                # # Cargar configuración por defecto desde nametags.json si existe
                # try:
                #     nametags_path = resource_path("nametags.json")
                #     if os.path.exists(nametags_path):
                #         with open(nametags_path, 'r', encoding='utf-8') as f:
                #             nametags_data = json.load(f)
                #             authorized = nametags_data.get('authorized', [])
                #             if authorized:
                #                 print(f"[Allio Config] Cargando usuarios autorizados desde nametags.json: {authorized}")
                #                 # Configurar instancias por defecto para usuarios autorizados si no están ya configuradas
                #                 for user in authorized:
                #                     if user not in self._memory_config.get('instances', {}):
                #                         self._memory_config.setdefault('instances', {})[user] = [0, 1]
                # except Exception as e:
                #     print(f"[Allio Config] Error cargando nametags.json: {e}")
                print("[Allio Config] Sistema de autorización deshabilitado - acceso universal activado")
                # ===== FIN CÓDIGO DESHABILITADO =====
                
                print("[Allio Config] Configuración inicializada")
                return

            config_path =os .path .join (os .path .dirname (os .path .abspath (sys .argv [0 ])),CONFIG_FILE )
            if not os .path .exists (config_path ):

                config_path =CONFIG_FILE 


            self ._username =getattr (self ,'_username',"")
            self ._custom_client =getattr (self ,'_custom_client',"")
            self ._server =getattr (self ,'_server',"")

            if os .path .exists (config_path ):
                with open (config_path ,'r',encoding ='utf-8')as f :
                    config =json .load (f )or {}

                if isinstance(config, dict):
                    try:
                        self._memory_config.update(config)
                        stored_session = config.get('auth_session')
                        if isinstance(stored_session, dict) and stored_session:
                            self.update_auth_session(stored_session)
                        else:
                            self._auth_session = {}
                    except Exception as e:
                        print(f"[Allio Config] Error applying stored config: {e}")
                        self._auth_session = {}
                else:
                    self._auth_session = {}

                saved_gamertag =config .get ('gamertag','')
                try:
                    cfg_client_token = config.get('client_token', '') if isinstance(config, dict) else ''
                    if cfg_client_token:
                        self._client_token = cfg_client_token
                except Exception:
                    pass

                if saved_gamertag and saved_gamertag !="Sin sesión":
                    print (f"[Allio Config] Cargando gamertag guardado: {saved_gamertag}")
                    self ._username =saved_gamertag 

                    short =saved_gamertag if len (saved_gamertag )<=12 else saved_gamertag [:11 ]+"…"
                    if hasattr (self ,'btn_profile'):
                        self .btn_profile .setText (short )
                        self .btn_profile .setToolTip (f"Xbox: {saved_gamertag}")

                    self .fetch_and_set_avatar (saved_gamertag )
                    print (f"[Allio Config] Auto-cargando avatar para {saved_gamertag}")

                    try :
                        inst_map =config .get ("instances",{})or {}
                        print (f"[Allio Config] Inst_map cargado: {inst_map}")
                        saved_list =inst_map .get (saved_gamertag ,[])
                        if hasattr (self ,"mapWidget")and saved_list :
                            try :
                                for idx in saved_list :
                                    try :



                                        self .mapWidget .show_instance_button (int (idx ),only_this =False ,save =False )
                                    except Exception :
                                        pass 
                            except Exception :
                                pass 
                    except Exception :
                        pass 
                else :
                    print ("[Allio Config] No hay gamertag guardado")


                try :
                    self ._custom_client =config .get ('custom_client','')or ''
                    self ._server =config .get ('server','')or ''
                    if self ._custom_client :
                        print (f"[Allio Config] Cliente custom configurado: {self._custom_client}")
                except Exception :
                    pass 
            else :
                # If there's no config file, start with defaults but do NOT create
                # a new config file automatically here. This prevents creating
                # `allio_config.json` the moment the app opens (user requested).
                print ("[Allio Config] Archivo de configuración no encontrado; arrancando con valores por defecto (no se creará archivo automáticamente)")
        except Exception as e :
            print (f"[Allio Config] Error cargando configuración: {e}")

    def save_config (self ):
        """Guarda la configuración actual en el archivo JSON o en un archivo temporal para ejecutables"""
        try :
            # Si es ejecutable, guardar en un archivo temporal en AppData
            if self._is_executable:
                cur_user = getattr(self, "_username", "") or ""
                
                # Actualizar configuración en memoria
                instances = self._memory_config.get("instances", {}) if isinstance(self._memory_config.get("instances", {}), dict) else {}
                
                if cur_user and cur_user != "Sin sesión" and hasattr(self, "mapWidget"):
                    try:
                        vis = []
                        for i, b in enumerate(self.mapWidget.inst_buttons):
                            try:
                                if b.isVisible():
                                    vis.append(i)
                            except Exception:
                                pass
                        instances[cur_user] = vis
                    except Exception:
                        pass
                
                custom_client = getattr(self, '_custom_client', '') or ''
                server = getattr(self, '_server', '') or ''
                minecraft_java_username = getattr(self, '_minecraft_java_username', '') or ''
                client_token = getattr(self, '_client_token', '') or ''
                
                self._memory_config.update({
                    'gamertag': cur_user if cur_user != "Sin sesión" else "",
                    'minecraft_java_username': minecraft_java_username,
                    'instances': instances,
                    'custom_client': custom_client,
                    'server': server,
                    'version': APP_TITLE,
                    'last_updated': str(time.time()),
                    'client_token': client_token,
                    'auth_session': self.get_auth_session(),
                })
                
                # Guardar en archivo temporal en AppData para persistencia entre sesiones
                try:
                    temp_dir = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'AllioClient')
                    os.makedirs(temp_dir, exist_ok=True)
                    temp_config = os.path.join(temp_dir, 'temp_config.json')
                    
                    with open(temp_config, 'w', encoding='utf-8') as f:
                        json.dump(self._memory_config, f, indent=2)
                    
                    print(f"[Allio Config] Configuración guardada en {temp_config}")
                except Exception as e:
                    print(f"[Allio Config] Error guardando configuración temporal: {e}")
                
                print(f"[Allio Config] Configuración guardada en memoria: gamertag='{cur_user}', instances_keys={list(instances.keys())}")
                return

            config_path =os .path .join (os .path .dirname (os .path .abspath (sys .argv [0 ])),CONFIG_FILE )


            existing ={}
            if os .path .exists (config_path ):
                try :
                    with open (config_path ,'r',encoding ='utf-8')as f :
                        existing =json .load (f )or {}
                except Exception :
                    existing ={}

            instances =existing .get ("instances",{})if isinstance (existing .get ("instances",{}),dict )else {}


            cur_user =getattr (self ,"_username","")or ""
            if cur_user and cur_user !="Sin sesión"and hasattr (self ,"mapWidget"):
                try :
                    vis =[]
                    for i ,b in enumerate (self .mapWidget .inst_buttons ):
                        try :
                            if b .isVisible ():
                                vis .append (i )
                        except Exception :
                            pass 
                    instances [cur_user ]=vis 
                except Exception :
                    pass 


            custom_client =getattr (self ,'_custom_client','')or ''
            server =getattr (self ,'_server','')or ''
            minecraft_java_username = getattr(self, '_minecraft_java_username', '') or existing.get('minecraft_java_username', '')  # SIN valor por defecto
            client_token_value = getattr(self, '_client_token', existing.get('client_token', '')) if isinstance(existing, dict) else getattr(self, '_client_token', '')

            config ={
            'gamertag':cur_user if cur_user !="Sin sesión"else "",
            'minecraft_java_username': minecraft_java_username,
            'instances':instances ,
            'custom_client':custom_client ,
            'server':server ,
            'version':APP_TITLE ,
            'last_updated':str (os .path .getmtime (__file__ )if os .path .exists (__file__ )else 0 ),
            'client_token': client_token_value or '',
            'auth_session': self.get_auth_session(),
            }

            with open (config_path ,'w',encoding ='utf-8')as f :
                json .dump (config ,f ,indent =2 ,ensure_ascii =False )


            try :
                print (f"[Allio Config] Configuración guardada: gamertag='{cur_user}', instances_keys={list(instances.keys())}, instances_for_user={instances.get(cur_user)}, custom_client='{custom_client}'")
            except Exception :
                print (f"[Allio Config] Configuración guardada: gamertag='{cur_user}', instances_keys={list(instances.keys())}, custom_client='{custom_client}'")
        except Exception as e :
            print (f"[Allio Config] Error guardando configuración: {e}")

    def get_auth_session(self) -> dict:
        """Devuelve una copia de la sesión de autenticación actual."""
        try:
            return dict(self._auth_session)
        except Exception:
            return {}

    def update_auth_session(self, session: dict | None):
        """Actualiza los tokens y metadatos de autenticación activos."""
        if not isinstance(session, dict) or not session:
            self._auth_session = {}
            try:
                if isinstance(self._memory_config, dict):
                    self._memory_config['auth_session'] = {}
            except Exception:
                pass
            return

        cleaned: dict[str, object] = {}
        for key, value in session.items():
            if value is None:
                continue
            if isinstance(value, str):
                if not value.strip():
                    continue
                cleaned[key] = value.strip()
            else:
                cleaned[key] = value

        if not cleaned:
            self._auth_session = {}
            try:
                if isinstance(self._memory_config, dict):
                    self._memory_config['auth_session'] = {}
            except Exception:
                pass
            return

        client_token = cleaned.get('client_token') or self._client_token or uuid.uuid4().hex
        self._client_token = client_token
        cleaned['client_token'] = client_token
        cleaned['updated_at'] = time.time()

        # Normalizar UUID de Minecraft si está presente
        raw_uuid = cleaned.get('minecraft_uuid') or cleaned.get('minecraft_uuid_nodash')
        if isinstance(raw_uuid, str):
            hex_uuid = raw_uuid.replace('-', '')
            if len(hex_uuid) == 32:
                dashed = f"{hex_uuid[0:8]}-{hex_uuid[8:12]}-{hex_uuid[12:16]}-{hex_uuid[16:20]}-{hex_uuid[20:32]}"
                cleaned['minecraft_uuid'] = dashed
                cleaned['minecraft_uuid_nodash'] = hex_uuid

        self._auth_session = cleaned

        try:
            if isinstance(self._memory_config, dict):
                self._memory_config['client_token'] = self._client_token
                self._memory_config['auth_session'] = dict(self._auth_session)
        except Exception:
            pass

        try:
            visible_keys = sorted(str(k) for k in self._auth_session.keys())
            print(f"[Allio Auth] Sesión actualizada con claves: {visible_keys}")
        except Exception:
            pass

    def ensure_minecraft_session(self, force_refresh: bool = False) -> dict:
        """Garantiza que exista un token de Minecraft válido en memoria.

        Devuelve la sesión actualizada (o vacía si no es posible asegurarla).
        """
        try:
            session = self.get_auth_session()
        except Exception:
            session = {}

        if not isinstance(session, dict):
            session = {}

        now = time.time()
        token = session.get('minecraft_token')
        uuid_nodash = session.get('minecraft_uuid_nodash') or ''
        token_expires = session.get('minecraft_token_expires_at')

        if token and uuid_nodash and not force_refresh:
            try:
                if token_expires and float(token_expires) - now <= 90:
                    force_refresh = True
            except Exception:
                pass
            if not force_refresh:
                print("[Allio Auth] Sesión Minecraft válida encontrada en memoria (sin refrescar).")
                return session

        refresh_token = session.get('ms_refresh_token')
        if not refresh_token:
            # No hay forma de renovar tokens automáticamente
            if token and uuid_nodash:
                print("[Allio Auth] No hay refresh_token, pero existe token actual. Se usará tal cual.")
                return session
            print("[Allio Auth] Sesión vacía o sin refresh_token disponible.")
            return session if token and uuid_nodash else {}

        try:
            print("[Allio] Actualizando sesión de Minecraft Java...")
            refresh_payload = {
                'client_id': MS_CLIENT_ID,
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token,
                'scope': MS_OAUTH_SCOPE,
            }
            token_resp = requests.post(MS_TOKEN_URL, data=refresh_payload, timeout=15)
            token_resp.raise_for_status()
            tokens = token_resp.json()

            access_token = tokens.get('access_token')
            if not access_token:
                print(f"[Allio] Error: refresh sin access_token ({tokens})")
                return session if token and uuid_nodash else {}

            session['ms_access_token'] = access_token
            try:
                if tokens.get('refresh_token'):
                    session['ms_refresh_token'] = tokens['refresh_token']
            except Exception:
                pass
            try:
                if tokens.get('expires_in'):
                    session['ms_token_expires_at'] = now + float(tokens['expires_in'])
            except Exception:
                pass

            headers = {'x-xbl-contract-version': '1'}
            payload = {
                "RelyingParty": "http://auth.xboxlive.com",
                "TokenType": "JWT",
                "Properties": {
                    "AuthMethod": "RPS",
                    "SiteName": "user.auth.xboxlive.com",
                    "RpsTicket": f"d={access_token}",
                },
            }
            user_resp = requests.post(XBOX_USER_AUTH_URL, json=payload, headers=headers, timeout=15)
            user_resp.raise_for_status()
            user_data = user_resp.json()
            user_token = user_data.get('Token')
            if not user_token:
                print(f"[Allio] Error renovando user_token: {user_data}")
                return session if token and uuid_nodash else {}

            payload = {
                "RelyingParty": "rp://api.minecraftservices.com/",
                "TokenType": "JWT",
                "Properties": {"UserTokens": [user_token], "SandboxId": "RETAIL"},
            }
            xsts_resp = requests.post(XBOX_XSTS_URL, json=payload, headers=headers, timeout=15)
            xsts_resp.raise_for_status()
            xsts_data = xsts_resp.json()
            display_claims = xsts_data.get('DisplayClaims', {})
            xuis = display_claims.get('xui') if isinstance(display_claims, dict) else None
            if not xuis:
                print(f"[Allio] Error renovando XSTS: {xsts_data}")
                return session if token and uuid_nodash else {}

            xui = xuis[0]
            session['xuid'] = xui.get('xid') or xui.get('xuid') or session.get('xuid')
            if xui.get('uhs'):
                session['xbox_userhash'] = xui.get('uhs')
            session['profile_name'] = xui.get('gtg') or session.get('profile_name')

            xsts_token = xsts_data.get('Token')
            if not xsts_token:
                print(f"[Allio] Error: XSTS sin token ({xsts_data})")
                return session if token and uuid_nodash else {}
            session['xsts_token'] = xsts_token

            userhash = session.get('xbox_userhash') or session.get('xuid') or ''
            if not userhash:
                print("[Allio] Error: no se encontró userhash para solicitar token de Minecraft.")
                return session if token and uuid_nodash else {}

            identity = {"identityToken": f"XBL3.0 x={userhash};{xsts_token}"}
            minecraft_resp = requests.post(MINECRAFT_LOGIN_URL, json=identity, timeout=15)
            if minecraft_resp.status_code != 200:
                print(f"[Allio] Error renovando token de Minecraft: {minecraft_resp.status_code} {minecraft_resp.text}")
                return session if token and uuid_nodash else {}
            minecraft_data = minecraft_resp.json()
            minecraft_token = minecraft_data.get('access_token')
            if not minecraft_token:
                print(f"[Allio] Respuesta inválida de Minecraft login: {minecraft_data}")
                return session if token and uuid_nodash else {}

            session['minecraft_token'] = minecraft_token
            try:
                if minecraft_data.get('expires_in'):
                    session['minecraft_token_expires_at'] = now + float(minecraft_data['expires_in'])
            except Exception:
                pass

            profile_headers = {'Authorization': f'Bearer {minecraft_token}'}
            profile_resp = requests.get(MINECRAFT_PROFILE_URL, headers=profile_headers, timeout=15)
            if profile_resp.status_code != 200:
                print(f"[Allio] Error obteniendo perfil de Minecraft Java: {profile_resp.status_code}")
                return session if token and uuid_nodash else {}

            profile = profile_resp.json()
            mc_uuid = profile.get('id')
            mc_name = profile.get('name')
            if mc_uuid:
                uuid_hex = mc_uuid.replace('-', '')
                if len(uuid_hex) == 32:
                    uuid_formatted = f"{uuid_hex[0:8]}-{uuid_hex[8:12]}-{uuid_hex[12:16]}-{uuid_hex[16:20]}-{uuid_hex[20:32]}"
                    session['minecraft_uuid'] = uuid_formatted
                    session['minecraft_uuid_nodash'] = uuid_hex
            if mc_name:
                session['minecraft_username'] = mc_name

            try:
                ent_resp = requests.get(MINECRAFT_ENTITLEMENTS_URL, headers=profile_headers, timeout=15)
                if ent_resp.status_code == 200:
                    entitlements = ent_resp.json().get('items', [])
                    owns_java = any(item.get('name') == 'product_minecraft' or item.get('name') == 'game_minecraft' for item in entitlements if isinstance(item, dict))
                    session['minecraft_java_entitled'] = owns_java
            except Exception:
                pass

            self.update_auth_session(session)
            try:
                self.save_config()
            except Exception:
                pass
            print(f"[Allio] Sesión de Minecraft renovada exitosamente.")
            return self.get_auth_session()
        except Exception as exc:
            print(f"[Allio] Error actualizando sesión de Minecraft: {exc}")
            return session if token and uuid_nodash else {}

    def _attempt_auto_repair_assets(self):
        """Intenta reparar automáticamente los assets de sonido copiando desde instalaciones locales.
        Ejecuta interacciones GUI (mensajes/diálogos) mediante QTimer.singleShot para correr en hilo GUI.
        """
        try:
            missing = check_minecraft_assets()
            if not missing:
                print("[Allio] Assets verificados: todo correcto.")
                return

            print("[Allio] Assets faltantes detectados, intentando reparación automática...")

            roots = [os.getcwd(), os.path.expanduser('~'), os.path.join(os.getenv('USERPROFILE', ''), 'Downloads')]
            candidates = find_local_minecraft_candidates(search_roots=roots, max_results=5)

            for c in candidates:
                try:
                    print(f"[Allio] Intentando copiar desde candidato: {c}")
                    ok = reparar_sonidos_minecraft(origen=c)
                    if ok:
                        def _notify_ok():
                            try:
                                if hasattr(self, 'notification') and self.notification is not None:
                                    try:
                                        self.notification.show_for("Assets de sonido restaurados", 3500)
                                        return
                                    except Exception:
                                        pass
                                QMessageBox.information(self, APP_TITLE, "Assets de sonido restaurados correctamente.")
                            except Exception:
                                pass
                        QTimer.singleShot(0, _notify_ok)
                        return
                except Exception as e:
                    print(f"[Allio] Error copiando desde candidato {c}: {e}")

            # Si no se pudo reparar automáticamente, pedir acción al usuario en hilo GUI
            def _ask_user():
                try:
                    mb = QMessageBox(self)
                    mb.setWindowTitle(APP_TITLE)
                    mb.setText("Se detectaron assets de sonido faltantes en tu instalación de Minecraft.")
                    mb.setInformativeText("¿Abrir el launcher oficial para descargar los assets o seleccionar manualmente una carpeta .minecraft para copiar los archivos desde allí?")
                    open_btn = mb.addButton("Abrir Launcher", QMessageBox.ButtonRole.AcceptRole)
                    select_btn = mb.addButton("Seleccionar Carpeta", QMessageBox.ButtonRole.ActionRole)
                    cancel_btn = mb.addButton("Cancelar", QMessageBox.ButtonRole.RejectRole)
                    mb.exec()
                    clicked = mb.clickedButton()
                    if clicked == open_btn:
                        launcher = self.find_minecraft_launcher()
                        if launcher:
                            try:
                                subprocess.Popen([launcher])
                            except Exception as e:
                                QMessageBox.warning(self, APP_TITLE, f"No se pudo abrir el launcher: {e}")
                        else:
                            QMessageBox.warning(self, APP_TITLE, "No se encontró el launcher oficial de Minecraft. Por favor instálalo desde minecraft.net")
                    elif clicked == select_btn:
                        folder = QFileDialog.getExistingDirectory(self, "Selecciona la carpeta raíz de Minecraft (la que contiene 'assets')", os.path.expanduser("~"))
                        if folder:
                            def _do_copy():
                                ok2 = reparar_sonidos_minecraft(origen=folder)
                                def _show_result():
                                    if ok2:
                                        QMessageBox.information(self, APP_TITLE, "Reparación completada correctamente.")
                                    else:
                                        QMessageBox.critical(self, APP_TITLE, "No se pudieron copiar los assets desde la carpeta seleccionada.")
                                QTimer.singleShot(0, _show_result)
                            threading.Thread(target=_do_copy, daemon=True).start()
                except Exception as e:
                    print(f"[Allio] Error mostrando diálogo de reparación: {e}")

            QTimer.singleShot(0, _ask_user)

        except Exception as e:
            print(f"[Allio] Error attempt_auto_repair_assets: {e}")


    def update_mask (self ):

        radius =22 

        try :
            if globals().get('USE_NATIVE_TITLEBAR', False):
                # When using native chrome we shouldn't apply a rounded mask that clips the
                # window frame/titlebar provided by the OS. Just clear any mask.
                try:
                    self.setMask(QRegion())
                except Exception:
                    pass
                return

            if self .isMaximized ():
                self .setMask (QRegion ())
                return 

            w =max (1 ,self .width ())
            h =max (1 ,self .height ())
            path =QPainterPath ()
            path .addRoundedRect (0.0 ,0.0 ,float (w ),float (h ),float (radius ),float (radius ))
            region =QRegion (path .toFillPolygon ().toPolygon ())
            self .setMask (region )
        except Exception as e :
            print (f"[Allio] update_mask error: {e}")

    def toggle_max_restore (self ):
        if self .isMaximized ():
            self .showNormal ()

            if self ._normal_geometry :
                self .setGeometry (self ._normal_geometry )
            self .update_mask ()
        else :

            self ._normal_geometry =self .geometry ()

            self .showMaximized ()

            self .setMask (QRegion ())


    def switch_to_map (self ):
        """Muestra la vista MapWidget (oculta mainBg e instancesWidget)."""
        try :

            if hasattr (self ,"mainBg"):
                try :self .mainBg .hide ()
                except Exception :pass 
            if hasattr (self ,"loadingWidget"):
                try :self .loadingWidget .hide ()
                except Exception :pass 
            if hasattr (self ,"instancesWidget"):
                try :self .instancesWidget .hide ()
                except Exception :pass 


            if hasattr (self ,"mapWidget"):
                self .mapWidget .show ()
                self .mapWidget .raise_ ()
                self .mapWidget .setFocus ()

            # ensure the floating play button is visible when showing the map
            try:
                if hasattr(self, 'play_btn') and self.play_btn is not None:
                    # No mostrar el botón Play si ya estamos en estado de lanzamiento
                    try:
                        # If launcher reports that Minecraft is running, show play_tile and hide floating button
                        if getattr(self, '_is_launching', False):
                            try:
                                if hasattr(self, 'play_tile') and self.play_tile is not None:
                                    self.play_tile.show()
                                    self.play_tile.raise_()
                                if hasattr(self, 'play_btn') and self.play_btn is not None:
                                    self.play_btn.setVisible(False)
                            except Exception:
                                pass
                        else:
                            if hasattr(self, 'play_tile') and self.play_tile is not None and self.play_tile.isVisible():
                                self.play_btn.setVisible(False)
                            else:
                                self.play_btn.setVisible(True)
                    except Exception:
                        try:
                            self.play_btn.setVisible(True)
                        except Exception:
                            pass
            except Exception:
                pass


            try :
                self .update_mask ()
            except Exception :
                pass 
        except Exception as e :
            print (f"[Allio] switch_to_map error: {e}")

    def show_notification (self ,text :str ,duration_ms :int =2000 ,parent_widget :QWidget |None =None ):
        """Muestra la notificación asegurando que se reposicione después del layout.
        Usa singleShot(0) para esperar al siguiente ciclo de eventos (cuando los widgets ya tengan tamaño).
        """
        try :
            if not hasattr (self ,'notification')or self .notification is None :
                return 

            target_parent =None 
            if parent_widget is not None :
                target_parent =parent_widget 
            elif hasattr (self ,'mapWidget')and self .mapWidget is not None :
                target_parent =self .mapWidget 
            elif hasattr (self ,'mainBg')and self .mainBg is not None :
                target_parent =self .mainBg 
            else :
                target_parent =self 
            try :
                if self .notification .parent ()!=target_parent :
                    self .notification .setParent (target_parent )
            except Exception :
                pass 

            def _reposition_and_show ():
                try :

                    if hasattr (target_parent ,'titleBar')and target_parent is not None :
                        try:
                            tb_h = _computed_titlebar_height(target_parent)
                        except Exception:
                            tb_h = 44
                    else :
                        tb_h =44 
                except Exception :
                    tb_h =44 
                try :
                    self .notification .adjustSize ()
                except Exception :
                    pass 
                try :
                    try :
                        parent_width =target_parent .width ()if target_parent is not None else self .width ()
                    except Exception :
                        parent_width =self .width ()
                    nx =parent_width -self .notification .width ()-NOTIF_RIGHT_MARGIN 
                    ny =tb_h +8 
                    self .notification .move (nx ,ny )
                    self .notification .raise_ ()
                except Exception :
                    pass 
                try :
                    self .notification .show_for (text ,duration_ms )
                except Exception :
                    try :
                        self .notification .show ()
                    except Exception :
                        pass 

            QTimer .singleShot (0 ,_reposition_and_show )
        except Exception as e :
            print (f"Error mostrando notificación: {e}")

    def switch_to_main (self ):
        """Vuelve a la vista principal (mainBg) y asegura ocultar instancesWidget."""
        try :

            if hasattr (self ,"mapWidget"):
                try :self .mapWidget .hide ()
                except Exception :pass 
            if hasattr (self ,"loadingWidget"):
                try :self .loadingWidget .hide ()
                except Exception :pass 
            if hasattr (self ,"instancesWidget"):
                try :self .instancesWidget .hide ()
                except Exception :pass 


            if hasattr (self ,"mainBg"):
                self .mainBg .show ()
                self .mainBg .raise_ ()
                self .mainBg .setFocus ()
            # hide floating play button when returning to main view
            try:
                if hasattr(self, 'play_btn') and self.play_btn is not None:
                    self.play_btn.setVisible(False)
            except Exception:
                pass

            try :
                self .update_mask ()
            except Exception :
                pass 
        except Exception as e :
            print (f"[Allio] switch_to_main error: {e}")


    def _on_main_avatar_ready(self, face: QPixmap):
        """Recibe el avatar y lo aplica al botón de perfil en la ventana principal"""
        try:
            if face and not face.isNull():
                print("[Allio Avatar] Avatar recibido en ventana principal")
                self._profile_image = face
                
                # Aplicar al botón de perfil si existe
                if hasattr(self, 'btn_profile'):
                    try:
                        # Crear un icono con el avatar y aplicarlo al botón
                        self.btn_profile.setIcon(QIcon(face))
                        size = min(face.width(), face.height(), 32)  # Ajustar tamaño máximo
                        self.btn_profile.setIconSize(QSize(size, size))
                        print(f"[Allio Avatar] Avatar aplicado al botón de perfil ({size}x{size})")
                    except Exception as e:
                        print(f"[Allio Avatar] Error aplicando avatar al botón: {e}")
        except Exception as e:
            print(f"[Allio Avatar] Error en _on_main_avatar_ready: {e}")
    
    def showEvent(self, event):
        """Maneja el evento de mostrar la ventana principal"""
        try:
            super().showEvent(event)
            
            # Si es la primera vez que se muestra la ventana y tenemos auto-login configurado
            if hasattr(self, '_is_startup') and self._is_startup:
                self._is_startup = False
                
                if hasattr(self, '_auto_login') and self._auto_login:
                    print("[Allio] Detectada necesidad de auto-login al inicio")
                    # Retrasar un poco el auto-login para asegurar que la interfaz esté completamente cargada
                    QTimer.singleShot(50, self._perform_auto_login)
        except Exception as e:
            print(f"[Allio] Error en showEvent: {e}")
    
    def load_profile_picture(self, username):
        """Carga la imagen del perfil/avatar del usuario utilizando fetch_and_set_avatar"""
        if not username or username == "Sin sesión":
            print("[Allio Avatar] No se puede cargar perfil: nombre de usuario inválido")
            return
        
        # Configurar el botón de perfil con el nombre de usuario
        if hasattr(self, 'btn_profile'):
            short = username if len(username) <= 12 else username[:11] + "…"
            self.btn_profile.setText(short)
            
            # Mostrar información en el tooltip
            self.btn_profile.setToolTip(f"Usuario: {username}")
        
        print(f"[Allio Avatar] Cargando perfil para: {username}")
        
        # Primero guardamos el nombre de usuario en la instancia para evitar problemas de acceso
        self._active_avatar_username = username
        
        # Iniciar la carga del avatar en segundo plano
        self.fetch_and_set_avatar(username)

    def _perform_auto_login(self):
        """Realiza el inicio de sesión automático y abre la ventana de instancias"""
        try:
            # IMPORTANTE: Primero intentar sincronizar con el launcher oficial de Microsoft
            print("[Allio Auto-Login] Sincronizando con launcher de Microsoft...")
            minecraft_dir = os.path.join(os.getenv('APPDATA', ''), '.minecraft')
            official_session = load_official_launcher_session(minecraft_dir)
            
            if official_session and official_session.get('minecraft_username'):
                print(f"[Allio Auto-Login] OK Sesión de Microsoft encontrada: {official_session.get('minecraft_username')}")
                # Actualizar la sesión con datos de Microsoft
                self.update_auth_session(official_session)
                self.save_config()
                # Actualizar username
                self._username = official_session.get('minecraft_username', self._username)
            else:
                print("[Allio Auto-Login] INFO No se encontró sesión en launcher de Microsoft, usando sesión guardada")
            
            # IMPORTANTE: Solo hacer auto-login si HAY una sesión válida guardada
            # NO intentar auto-login si es la primera vez que se ejecuta
            
            # Verificar que tengamos una sesión guardada
            if not hasattr(self, '_auth_session') or not self._auth_session:
                print("[Allio Auto-Login] ERROR No hay sesión guardada - mostrando pantalla de login")
                return
            
            # Verificar que la sesión tenga datos válidos
            session = self._auth_session
            if not isinstance(session, dict):
                print("[Allio Auto-Login] ERROR Sesión inválida - mostrando pantalla de login")
                return
                
            # Verificar que tengamos un username
            username = self._username
            if not username or username == "Sin sesión":
                print("[Allio Auto-Login] ERROR No hay usuario en la sesión - mostrando pantalla de login")
                return
            
            # Verificar que tengamos token y UUID (aunque sea offline)
            has_token = bool(session.get('minecraft_token'))
            has_uuid = bool(session.get('minecraft_uuid'))
            
            if not has_token or not has_uuid:
                print(f"[Allio Auto-Login] ERROR Sesión incompleta (token={has_token}, uuid={has_uuid}) - mostrando pantalla de login")
                return
                
            print(f"[Allio Auto-Login] OK Sesión válida encontrada para '{username}', iniciando auto-login...")
            
            # Ocultar la pantalla principal para evitar parpadeos
            if hasattr(self, "mainBg"):
                try:
                    self.mainBg.hide()
                except Exception as e:
                    print(f"[Allio Auto-Login] Error ocultando mainBg: {e}")
                
            # Si llegamos aquí, el usuario está autorizado - preparar todo para abrir la ventana de instancias
            print(f"[Allio Auto-Login] Iniciando sesión automática para: {username}")
            
            # Cargar el avatar/skin del usuario
            try:
                self.load_profile_picture(username)
                print(f"[Allio Auto-Login] Avatar cargado para: {username}")
            except Exception as e:
                print(f"[Allio Auto-Login] Error cargando avatar: {e}")
            
            # Mostrar notificación de inicio de sesión
            try:
                parent_widget = self.instancesWidget if hasattr(self, 'instancesWidget') else self
                self.show_notification(f"Sesión iniciada: {username}", duration_ms=2000, parent_widget=parent_widget)
            except Exception as e:
                print(f"[Allio Auto-Login] Error mostrando notificación: {e}")
            
            # Abrir instancias inmediatamente para evitar parpadeos de la pantalla de login
            try:
                self.open_instances()
            except Exception as e:
                print(f"[Allio Auto-Login] Error abriendo instancias: {e}")
                # Si falla, intentar de nuevo después de un breve retraso
                QTimer.singleShot(100, self.open_instances)
            
        except Exception as e:
            print(f"[Allio Auto-Login] Error en inicio de sesión automático: {e}")
    
    def open_instances (self ):
        """Muestra la vista InstancesWidget (oculta otras vistas)."""
        try :
            if hasattr (self ,"mainBg"):
                try :self .mainBg .hide ()
                except Exception :
                    pass 
            if hasattr (self ,"mapWidget"):
                try :self .mapWidget .hide ()
                except Exception :
                    pass 
            if hasattr (self ,"loadingWidget"):
                try :self .loadingWidget .hide ()
                except Exception :
                    pass 
            if hasattr (self ,"instancesWidget"):
                self .instancesWidget .show ()
                self .instancesWidget .raise_ ()
                self .instancesWidget .setFocus ()
            # Hide floating play button when showing instances, unless play_tile indicates otherwise
            try:
                if hasattr(self, 'play_btn') and self.play_btn is not None:
                    try:
                        if hasattr(self, 'play_tile') and self.play_tile is not None and self.play_tile.isVisible():
                            self.play_btn.setVisible(False)
                        else:
                            # For instances view, generally hide the floating play button
                            self.play_btn.setVisible(False)
                    except Exception:
                        self.play_btn.setVisible(False)
            except Exception:
                pass
            try :
                self .update_mask ()
            except Exception :
                pass 
        except Exception as e :
            print (f"[Allio] open_instances error: {e}")

    def _on_loading_finished (self ,ok :bool ,face ,gamertag :str ):
        """Maneja el resultado de la verificación del gamertag realizada por LoadingWidget."""
        try :
            print (f"[Allio] _on_loading_finished: ok={ok}, gamertag={gamertag}, face={'yes' if face else 'no'}")
            if ok :
                print (f"[Allio] Gamertag '{gamertag}' verificado. Procediendo.")
                
                # Usar el username de Minecraft Java si está configurado, sino usar el gamertag
                final_username = gamertag
                try:
                    config_file = "allio_config.json"
                    if os.path.exists(config_file):
                        with open(config_file, 'r', encoding='utf-8') as f:
                            config = json.load(f)
                            minecraft_java_username = config.get('minecraft_java_username', '')
                            if minecraft_java_username:
                                final_username = minecraft_java_username
                                print(f"[Allio] Usando username de Minecraft Java en perfil: {final_username}")
                except Exception as e:
                    print(f"[Allio] Error leyendo config para username de perfil: {e}")
                
                self ._username = final_username 

                try :
                    config_path =os .path .join (os .path .dirname (os .path .abspath (sys .argv [0 ])),CONFIG_FILE )
                    if not os .path .exists (config_path ):
                        config_path =CONFIG_FILE 
                    inst_map ={}
                    if os .path .exists (config_path ):
                        try :
                            with open (config_path ,'r',encoding ='utf-8')as f :
                                cfg =json .load (f )or {}
                                inst_map =cfg .get ('instances',{})or {}
                        except Exception :
                            inst_map ={}
                    saved_list =inst_map .get (gamertag ,[])if isinstance (inst_map ,dict )else []
                    if hasattr (self ,'mapWidget')and saved_list :
                        try :
                            for idx in saved_list :
                                try :

                                    self .mapWidget .show_instance_button (int (idx ),only_this =False ,save =False )
                                except Exception :
                                    pass 
                        except Exception :
                            pass 
                except Exception :
                    pass 
                if face :
                    try :



    
                        self .set_profile_avatar (face )
                    except Exception :
                        pass 

                    try :
                        self .avatarReady .emit (face )
                    except Exception :
                        pass 

                    # Actualizar Discord RPC con el username
                    try:
                        if hasattr(self, 'discord_rpc') and self.discord_rpc.connected:
                            self.discord_rpc.set_idle(final_username)
                    except Exception as e:
                        print(f"[Discord RPC] Error actualizando presencia tras login: {e}")

                    try :
                        if hasattr (self ,'mapWidget')and hasattr (self .mapWidget ,'_small_avatar'):
                            try :
                                self .mapWidget ._small_avatar .setIcon (QIcon (face ))
                                self .mapWidget ._small_avatar .setIconSize (face .size ())
                            except Exception :
                                pass 
                        # --- Verificación automática de assets de sonido ---
                        missing_assets = check_minecraft_assets()
                        if missing_assets:
                            # intentar encontrar instalaciones locales válidas y copiar assets automáticamente
                            candidates = find_local_minecraft_candidates([os.getcwd(), os.path.expanduser('~')])
                            repaired = False
                            source_used = None
                            for c in candidates:
                                try:
                                    if reparar_sonidos_minecraft(origen=c):
                                        repaired = True
                                        source_used = c
                                        break
                                except Exception:
                                    pass
                            if repaired:
                                try:
                                    QMessageBox.information(self, "Assets reparados", f"Se copiaron assets desde: {source_used}")
                                except Exception:
                                    print(f"[Allio] Se copiaron assets desde: {source_used}")
                            else:
                                msg = ("Faltan archivos esenciales de Minecraft para sonido y recursos.\n"
                                       "Abre el launcher oficial o selecciona otra instalación para copiar los assets.\n\n"
                                       "Archivos/carpetas faltantes:\n" + '\n'.join(missing_assets))
                                try:
                                    # En lugar de mostrar el diálogo interactivo, registrar y tratar de abrir
                                    # el launcher automáticamente. Esto elimina la ventana emergente.
                                    print("[Allio] Faltan assets de Minecraft:\n" + msg)
                                    launcher_paths = [
                                        r"C:\Program Files (x86)\Minecraft Launcher\MinecraftLauncher.exe",
                                        r"C:\Program Files\Minecraft Launcher\MinecraftLauncher.exe",
                                        os.path.join(os.getenv('LOCALAPPDATA') or '', 'Programs', 'Minecraft Launcher', 'MinecraftLauncher.exe')
                                    ]
                                    launcher_path = None
                                    for path in launcher_paths:
                                        try:
                                            if path and os.path.exists(path):
                                                launcher_path = path
                                                break
                                        except Exception:
                                            pass
                                    if launcher_path:
                                        try:
                                            subprocess.Popen([launcher_path])
                                            print(f"[Allio] Launcher abierto automáticamente: {launcher_path}")
                                        except Exception as e:
                                            print(f"[Allio] Error abriendo launcher: {e}")
                                    else:
                                        try:
                                            webbrowser.open('minecraft:')
                                            print("[Allio] Intentado protocolo minecraft: abrir launcher.")
                                        except Exception:
                                            print("[Allio] No se encontró launcher ni se pudo abrir protocolo minecraft.")
                                except Exception:
                                    print("[Allio] ADVERTENCIA: " + msg)
                    except Exception :
                        pass 


                if hasattr (self ,'notification')and self .notification is not None :
                    try :

                        if hasattr (self ,'mapWidget')and self .notification .parent ()!=self .mapWidget :
                            self .notification .setParent (self .mapWidget )
                        try:
                            tb_h = _computed_titlebar_height(self.mapWidget)
                        except Exception:
                            tb_h = 44
                    except Exception :
                        tb_h =44 
                    self .notification .adjustSize ()
                    nx =max (0 ,self .mapWidget .width ()-self .notification .width ()-NOTIF_RIGHT_MARGIN )if hasattr (self ,'mapWidget')else max (0 ,self .width ()-self .notification .width ()-NOTIF_RIGHT_MARGIN )
                    ny =tb_h +8 
                    try :
                        self .notification .move (nx ,ny )
                    except Exception :
                        pass 


                try :
                    if hasattr (self ,'loadingWidget')and self .loadingWidget is not None :
                        try :
                            self .loadingWidget .stop ()
                        except Exception :
                            pass 
                        try :
                            self .loadingWidget .hide ()
                        except Exception :
                            pass 
                except Exception :
                    pass 

                try :

                    config_path =os .path .join (os .path .dirname (os .path .abspath (sys .argv [0 ])),CONFIG_FILE )
                    if not os .path .exists (config_path ):
                        config_path =CONFIG_FILE 
                    cfg ={}
                    if os .path .exists (config_path ):
                        try :
                            with open (config_path ,'r',encoding ='utf-8')as f :
                                cfg =json .load (f )or {}
                        except Exception :
                            cfg ={}
                    inst_map =cfg .get ('instances',{})if isinstance (cfg .get ('instances',{}),dict )else {}
                    try :
                        print (f"[Allio][DBG] Loaded inst_map keys={list(inst_map.keys()) if isinstance(inst_map, dict) else repr(inst_map)}")
                    except Exception :
                        pass 


                    # ===== DESHABILITADO: TODO EL SISTEMA DE AUTORIZACIÓN =====
                    # Ahora TODOS los usuarios tienen acceso sin restricciones
                    # No se verifica nametags.json ni instances
                    
                    print(f"[Allio][AUTH] Acceso universal habilitado - usuario '{gamertag}' puede acceder")
                    
                    # Abrir directamente InstancesWidget para TODOS los usuarios
                    try :
                        if hasattr (self ,'notification') and self .notification is not None :
                            try :
                                parent_widget = self.instancesWidget if hasattr(self, 'instancesWidget') and self.instancesWidget is not None else self
                                self .show_notification ("Logged in", duration_ms =1400, parent_widget=parent_widget)
                            except Exception :
                                pass 

                        if hasattr (self ,'instancesWidget'):
                            try:
                                print(f"[Allio] Abriendo InstancesWidget para '{gamertag}' (acceso universal)")
                            except Exception:
                                pass
                            self .open_instances ()
                            return 
                    except Exception as e:
                        print(f"[Allio] Error abriendo instancias: {e}")
                        pass
                    
                    # ===== FIN CÓDIGO DESHABILITADO =====
                except Exception :
                    pass 

                try :
                    if hasattr (self ,'notification')and self .notification is not None :
                        try :
                            try :
                                try :
                                    self .notification .icon_label .setStyleSheet ("border-radius:18px; background: #2ecc71; color: white; font-weight:700; text-align:center; border:1px solid rgba(0,0,0,0.06);")
                                    self .notification .icon_label .setText ("✓")
                                    try :
                                        self .notification .progress .setStyleSheet ("QProgressBar{background:rgba(0,0,0,0.06); border-radius:3px;} QProgressBar::chunk{background:#2ecc71; border-radius:3px;}")
                                    except Exception :
                                        pass 
                                except Exception :
                                    pass 
                                # Mostrar la notificación dentro de InstancesWidget si está disponible (mejor visibilidad)
                                parent_widget = self.instancesWidget if hasattr(self, 'instancesWidget') and self.instancesWidget is not None else (self.mapWidget if hasattr(self, 'mapWidget') and self.mapWidget is not None else self)
                                self .show_notification ("Logged in",duration_ms =2200 ,parent_widget=parent_widget)
                            except Exception :
                                try :
                                    self .notification .show_for ("Logged in",duration_ms =2200 )
                                except Exception :
                                    pass 
                        except Exception :
                            pass 
                except Exception :
                    pass
                # Si el login vino de LoginDialog o del OAuth y el usuario pidió abrir Instances, hacerlo ahora
                try:
                    flag = getattr(self, '_open_instances_on_success', False)
                    try:
                        print(f"[Allio] _on_loading_finished: _open_instances_on_success flag = {flag}")
                    except Exception:
                        pass
                    if flag:
                        try:
                            if hasattr(self, 'open_instances'):
                                try:
                                    print(f"[Allio] _on_loading_finished: opening InstancesWidget due to flag for '{gamertag}'")
                                except Exception:
                                    pass
                                self.open_instances()
                        except Exception:
                            pass
                        try:
                            # clear the flag
                            if hasattr(self, '_open_instances_on_success'):
                                try:
                                    delattr(self, '_open_instances_on_success')
                                except Exception:
                                    try:
                                        setattr(self, '_open_instances_on_success', False)
                                    except Exception:
                                        pass
                        except Exception:
                            pass
                except Exception:
                    pass
            else :
                print (f"[Allio] Gamertag '{gamertag}' NO encontrado.")
                try :
                    if hasattr (self ,'loadingWidget')and self .loadingWidget is not None :
                        try :
                            self .loadingWidget .stop ()
                        except Exception :
                            pass 
                        try :
                            self .loadingWidget .hide ()
                        except Exception :
                            pass 
                except Exception :
                    pass 

                try :
                    if hasattr (self ,'notification')and self .notification is not None :
                        try :

                            try :
                                # DESHABILITADO: target_parent = getattr(self, 'unauthorized_widget', None) or self .mainBg
                                target_parent = self .mainBg
                                self .show_notification ("Error: Gamertag no encontrado",duration_ms =2600 ,parent_widget =target_parent )
                                QTimer .singleShot (10 ,lambda :self .notification .show_error (f"Gamertag '{gamertag}' no encontrado",duration_ms =2200 ))
                            except Exception :
                                # DESHABILITADO: target_parent = getattr(self, 'unauthorized_widget', None) or self .mainBg
                                target_parent = self .mainBg
                                self .notification .show_error (f"Gamertag '{gamertag}' no encontrado",duration_ms =2200 )
                        except Exception :
                            pass 
                except Exception :
                    pass 
                try :
                    self .switch_to_main ()
                except Exception :
                    pass 

                try :
                    if hasattr (self ,'notification')and self .notification is not None :
                        try :

                            try :
                                # DESHABILITADO: target_parent = getattr(self, 'unauthorized_widget', None) or self .mainBg
                                target_parent = self .mainBg
                                self .show_notification ("Gamertag no encontrado",duration_ms =2600 ,parent_widget =target_parent )

                                QTimer .singleShot (10 ,lambda :self .notification .show_error (f"Error: {gamertag} not found",duration_ms =2200 ))
                            except Exception :
                                self .notification .show_error (f"Error: {gamertag} not found",duration_ms =2200 )
                        except Exception :
                            pass 
                except Exception :
                    pass 
        except Exception as e :
            print (f"[Allio] Error procesando resultado de carga: {e}")
            try :
                if hasattr (self ,'loadingWidget')and self .loadingWidget is not None :
                    try :
                        self .loadingWidget .stop ()
                    except Exception :
                        pass 
                    try :
                        self .loadingWidget .hide ()
                    except Exception :
                        pass 
            except Exception :
                pass 
            QMessageBox .warning (self ,APP_TITLE ,"Error verificando el Gamertag.")

    def show_loading_with (self ,gamertag :str ):
        """Muestra la pantalla de carga y lanza la comprobación del gamertag."""
        try :

            try :
                if isinstance (gamertag ,str )and len (gamertag )>MAX_GAMERTAG_LEN :

                    try :
                        if hasattr (self ,'notification')and self .notification is not None :
                            # DESHABILITADO: target_parent = getattr(self, 'unauthorized_widget', None) or self .mainBg
                            target_parent = self .mainBg
                            self .show_notification ("Gamertag inválido",duration_ms =2600 ,parent_widget =target_parent )
                            QTimer .singleShot (10 ,lambda :self .notification .show_error ("Gamertag demasiado largo",duration_ms =2200 ))
                    except Exception :
                        pass 
                    try :
                        self .switch_to_main ()
                    except Exception :
                        pass 
                    return 
            except Exception :
                pass 
            if hasattr (self ,"mainBg"):
                try :
                    self .mainBg .hide ()
                except Exception :
                    pass 
            if hasattr (self ,"mapWidget"):
                try :
                    self .mapWidget .hide ()
                except Exception :
                    pass 
            print (f"[Allio] show_loading_with: mostrando loadingWidget para '{gamertag}'")
            if hasattr (self ,"loadingWidget"):
                print ("[Allio] show_loading_with: loadingWidget.show()")
                self .loadingWidget .show ()
                self .loadingWidget .raise_ ()

                try:
                    print("[Allio] show_loading_with: processEvents() antes de start_check")
                    QApplication.processEvents()
                except Exception as evt_err:
                    print(f"[Allio] show_loading_with: processEvents error: {evt_err}")

                def _start_check():
                    try:
                        if hasattr(self, 'loadingWidget') and self.loadingWidget is not None:
                            self.loadingWidget.start_check(gamertag)
                    except Exception as start_err:
                        print(f"[Allio] show_loading_with: start_check error: {start_err}")

                try:
                    print("[Allio] show_loading_with: programando start_check con singleShot(180)")
                    QTimer.singleShot(180, _start_check)
                except Exception as timer_err:
                    print(f"[Allio] show_loading_with: singleShot error: {timer_err}, llamando start_check directo")
                    _start_check()

        except Exception:
            pass 


        try :
            self ._btn_normal_style ="border: none; background: none;"
            self ._btn_hover_style ="border: none; background: rgba(255,255,255,0.05);"

            self .installEventFilter (self )
        except Exception :
            pass 

    def eventFilter (self ,watched ,event ):
        try :
            if watched is self and event .type ()==QEvent .Type .Enter :

                for b in (self .btn_min ,self .btn_max ,self .btn_close ):
                    try :
                        b .setStyleSheet (self ._btn_hover_style )
                    except Exception :
                        pass 
                return False 
            if watched is self and event .type ()==QEvent .Type .Leave :
                for b in (self .btn_min ,self .btn_max ,self .btn_close ):
                    try :
                        b .setStyleSheet (self ._btn_normal_style )
                    except Exception :
                        pass 
                return False 
        except Exception :
            pass 
        return super ().eventFilter (watched ,event )


        try :

            server =getattr (self ,'_server','')or ''
            if server :
                try :
                    self .ensure_external_server (server )
                except Exception :
                    pass 
            subprocess .Popen (["start","minecraft://"],shell =True )
        except Exception :
            pass 
        try :
            subprocess .Popen (['explorer.exe','shell:AppsFolder\\Microsoft.MinecraftUWP_8wekyb3d8bbwe!App'])
        except Exception :
            pass 

        try :
            self .close ()
        except Exception :
            try :
                self .hide ()
            except Exception :
                pass 

    def ensure_external_server (self ,address :str ,name :str ="Allio Server"):
        """Inserta una entrada en external_servers.txt para que el servidor aparezca en la lista de servidores de Bedrock.
        address debe tener formato ip:port o hostname:port.
        Esto es una operación sincrónica y no valida el servidor.
        """
        try :
            if not address :
                return False 
            base =Path (os .getenv ("LOCALAPPDATA",""))/"Packages"/"Microsoft.MinecraftUWP_8wekyb3d8bbwe"/"LocalState"/"games"/"com.mojang"/"minecraftpe"
            base .mkdir (parents =True ,exist_ok =True )
            ext_file =base /"external_servers.txt"


            try :
                existing =[]
                if ext_file .exists ():
                    with open (ext_file ,'r',encoding ='utf-8')as f :
                        existing =[line .strip ()for line in f if line .strip ()]
                entry =f"{address}#{name}"
                if entry not in existing :
                    existing .append (entry )
                    with open (ext_file ,'w',encoding ='utf-8')as f :
                        for line in existing :
                            f .write (line +"\n")
                print (f"[Allio] external_servers updated: {ext_file}")
                return True 
            except Exception as e :
                print (f"[Allio] Error escribiendo external_servers: {e}")
                return False 
        except Exception as e :
            print (f"[Allio] ensure_external_server error: {e}")
            return False 

    def fetch_avatar_urls (self ,gamertag :str ):
        encoded =urllib .parse .quote (gamertag )
        
        # Intentar obtener UUID de Minecraft primero para URLs más precisas
        minecraft_uuid = self.get_minecraft_uuid(gamertag)
        
        urls = []
        
        # Si tenemos UUID, usar APIs más confiables primero
        if minecraft_uuid:
            uuid_no_dashes = minecraft_uuid.replace('-', '')
            uuid_encoded = urllib.parse.quote(minecraft_uuid)
            urls.extend([
                # APIs más confiables primero
                f"https://visage.surgeplay.com/face/64/{uuid_no_dashes}",
                f"https://api.ashcon.app/mojang/v2/avatar/{uuid_no_dashes}",
                f"https://minotar.net/helm/{uuid_no_dashes}/64.png",
                f"https://mineskin.eu/helm/{uuid_no_dashes}/64.png",
                f"https://cravatar.eu/helmavatar/{uuid_no_dashes}/64.png",
                # Crafatar al final por timeout
                f"https://mc-heads.net/avatar/{uuid_no_dashes}/64",
                f"https://crafatar.com/avatars/{uuid_no_dashes}?size=64&overlay&default=MHF_Steve"
            ])
        
        # URLs que funcionan con username
        urls.extend([
            f"https://visage.surgeplay.com/face/64/{encoded}",
            f"https://api.ashcon.app/mojang/v2/avatar/{encoded}",
            f"https://minotar.net/helm/{encoded}/64.png",
            f"https://mineskin.eu/helm/{encoded}/64.png",
            f"https://cravatar.eu/helmavatar/{encoded}/64.png",
            f"https://mc-heads.net/avatar/{encoded}/64",
            f"https://crafatar.com/avatars/{encoded}?size=64&overlay&default=MHF_Steve",
            # Mantener Xbox como fallback final
            f"https://avatar-ssl.xboxlive.com/avatar/{encoded}/avatarpic-l.png",
            f"https://avatar-ssl.xboxlive.com/avatar/{encoded}/avatar-body.png"
        ])
        
        return urls
    
    def get_minecraft_uuid(self, username: str) -> Optional[str]:
        """Intenta obtener el UUID de Minecraft para un username dado"""
        try:
            # API de Mojang para obtener UUID
            url = f"https://api.mojang.com/users/profiles/minecraft/{urllib.parse.quote(username)}"
            headers = {
                "User-Agent": "AllioClient/2.0"
            }
            
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as response:
                data = response.read()
                
            if data:
                import json
                profile = json.loads(data.decode('utf-8'))
                uuid = profile.get('id')
                if uuid:
                    # Formatear UUID con guiones
                    formatted_uuid = f"{uuid[:8]}-{uuid[8:12]}-{uuid[12:16]}-{uuid[16:20]}-{uuid[20:]}"
                    print(f"[Allio Avatar] UUID encontrado para {username}: {formatted_uuid}")
                    return formatted_uuid
        except Exception as e:
            print(f"[Allio Avatar] No se pudo obtener UUID para {username}: {e}")
        
        return None
    
    def generate_username_variants(self, username: str) -> list:
        """Genera variantes del username para buscar skins"""
        variants = []
        
        # Remover números al final (común en gamertags de Xbox)
        import re
        base_name = re.sub(r'\d+$', '', username)
        if base_name and base_name != username:
            variants.append(base_name)
        
        # Variantes comunes
        if len(username) > 3:
            # Sin números finales
            no_numbers = re.sub(r'[0-9]+$', '', username)
            if no_numbers != username:
                variants.append(no_numbers)
            
            # Versiones con guiones bajos
            variants.append(username.replace(' ', '_'))
            
            # Versiones sin espacios
            variants.append(username.replace(' ', ''))
            
            # Lowercase/uppercase variants
            if username != username.lower():
                variants.append(username.lower())
            if username != username.upper():
                variants.append(username.upper())
        
        # Remover duplicados y el username original
        variants = list(set(variants))
        if username in variants:
            variants.remove(username)
            
        return variants[:5]  # Limitar a 5 variantes para no sobrecargar
    
    def is_default_skin(self, image_data: bytes) -> bool:
        """Detecta si una imagen es una skin por defecto (Steve/Alex)"""
        try:
            # Verificar tamaño de archivo - skins por defecto suelen ser muy pequeñas
            if len(image_data) < 600:  # Muy pequeña, probablemente por defecto
                return True
            
            # Las skins por defecto de Steve/Alex tienen tamaños específicos conocidos
            known_default_sizes = [388, 549, 646, 762, 826, 900, 1024, 1264]  # Tamaños comunes de Steve/Alex
            if len(image_data) in known_default_sizes:
                return True
            
            # Para imágenes más grandes, verificar contenido
            if len(image_data) > 2000:
                # Probablemente es una skin personalizada si es grande
                return False
                
            return False
        except Exception:
            return False

    def fetch_and_set_avatar (self ,gamertag :str ):
        def worker ():
            print (f"[Allio Avatar] Iniciando búsqueda para: {gamertag}")
            
            # Determinar qué username usar para la búsqueda de skin
            search_username = _ensure_username(gamertag)
            
            # Intentar leer el username de Minecraft Java desde la configuración
            try:
                config_file = "allio_config.json"
                if os.path.exists(config_file):
                    with open(config_file, 'r', encoding='utf-8') as f:
                        config = json.load(f)
                        minecraft_java_username = config.get('minecraft_java_username', '')
                        if minecraft_java_username:
                            search_username = minecraft_java_username
                            print(f"[Allio Avatar] OK Usando username de Minecraft Java desde config: {search_username}")
                        else:
                            print(f"[Allio Avatar] AVISO No se encontró minecraft_java_username en config, usando: {search_username}")
                else:
                    print(f"[Allio Avatar] AVISO Config file no encontrado, usando: {search_username}")
            except Exception as e:
                print(f"[Allio Avatar] AVISO Error leyendo config: {e}, usando: {search_username}")
            
            # Verificar si hay una caché local del avatar (usar search_username para la caché)
            cache_dir = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'AllioClient', 'avatars')
            cache_file = os.path.join(cache_dir, f"{search_username.lower()}.png")
            
            try:
                if os.path.exists(cache_file) and os.path.getsize(cache_file) > 100:
                    print(f"[Allio Avatar] Intentando cargar avatar desde caché: {cache_file}")
                    cached_pix = QPixmap(cache_file)
                    if not cached_pix.isNull() and cached_pix.width() > 16 and cached_pix.height() > 16:
                        print(f"[Allio Avatar] OK Avatar cargado desde caché: {cached_pix.width()}x{cached_pix.height()}")
                        self.avatarStatus.emit(f"Avatar cargado desde caché para {search_username}", True)
                        face = self.circularize(cached_pix, 48)
                        self.avatarReady.emit(face)
                        return
            except Exception as e:
                print(f"[Allio Avatar] Error cargando avatar desde caché: {e}")

            # Si no hay caché o falla, buscar skin local
            local_skin = self.find_local_bedrock_skin(search_username)
            if local_skin:
                print(f"[Allio Avatar] OK Skin local encontrado para {search_username}: {local_skin.width()}x{local_skin.height()}")
                self.avatarStatus.emit(f"Skin local de Minecraft Java cargado para {search_username}", True)
                face = self.circularize(local_skin, 48)
                self.avatarReady.emit(face)
                
                # Guardar en caché para uso futuro
                try:
                    os.makedirs(cache_dir, exist_ok=True)
                    local_skin.save(cache_file, "PNG")
                    print(f"[Allio Avatar] Avatar guardado en caché: {cache_file}")
                except Exception as e:
                    print(f"[Allio Avatar] Error guardando avatar en caché: {e}")
                
                return 

            print(f"[Allio Avatar] No se encontró skin local, buscando online para {search_username}")

            # Si no hay skin local, buscar online
            pix = self.download_avatar(search_username)
            if pix is None:
                # Si no encontramos con el search_username, intentar buscar con diferentes variantes
                variants = self.generate_username_variants(search_username)
                for variant in variants:
                    print(f"[Allio Avatar] Intentando variante de username: {variant}")
                    pix = self.download_avatar(variant)
                    if pix is not None:
                        print(f"[Allio Avatar] OK Skin encontrada con variante: {variant}")
                        break
                        
            if pix is None:
                print(f"[Allio Avatar] No se encontró avatar online para {search_username}, usando placeholder")
                # Mensaje específico para usuarios sin Minecraft Java
                if search_username and search_username.lower().endswith(('1', '2', '3', '4', '5', '6', '7', '8', '9', '0')):
                    self.avatarStatus.emit(f"'{search_username}' parece ser un gamertag de Xbox. Para mostrar tu skin de Minecraft Java, necesitas vincular o comprar Minecraft Java Edition.", False)
                else:
                    self.avatarStatus.emit(f"No se pudo obtener skin de '{search_username}'. Usando placeholder.", False)
                pix = self.build_placeholder_avatar(search_username)
            else:
                print(f"[Allio Avatar] Avatar online encontrado para {search_username}: {pix.width()}x{pix.height()}")
                self.avatarStatus.emit(f"Skin de Minecraft Java cargado para {search_username}", True)
                
                # Guardar en caché para uso futuro
                try:
                    os.makedirs(cache_dir, exist_ok=True)
                    pix.save(cache_file, "PNG")
                    print(f"[Allio Avatar] Avatar guardado en caché: {cache_file}")
                except Exception as e:
                    print(f"[Allio Avatar] Error guardando avatar en caché: {e}")
            
            face = self.circularize(pix, 48)
            print(f"[Allio Avatar] Enviando avatar circular: {face.width()}x{face.height()}")
            self.avatarReady.emit(face)
        threading .Thread (target =worker ,daemon =True ).start ()

    def _ensure_offline_skin_assets(self, minecraft_dir: str, username: str) -> None:
        """Garantiza que exista un archivo de skin local para sesiones offline."""
        try:
            if not username:
                return

            username = username.strip()
            if not username:
                return

            skins_dir = Path(minecraft_dir) / 'assets' / 'skins'
            skins_dir.mkdir(parents=True, exist_ok=True)
            skin_path = skins_dir / f"{username}.png"

            # Si ya existe una skin razonable, no tocarla.
            if skin_path.exists() and skin_path.stat().st_size > 600:
                return

            cache_root = Path(os.getenv('APPDATA', Path.home())) / 'AllioClient' / 'avatars'
            cache_path = cache_root / f"{username.lower()}.png"
            if cache_path.exists() and cache_path.stat().st_size > 600:
                shutil.copy2(cache_path, skin_path)
                print(f"[Allio Avatar] Skin offline restaurada desde caché: {skin_path}")
                return

            skin_bytes = self._download_mojang_skin(username)
            if not skin_bytes and username.lower() != username:
                skin_bytes = self._download_mojang_skin(username.lower())

            if skin_bytes:
                skin_path.write_bytes(skin_bytes)
                try:
                    cache_root.mkdir(parents=True, exist_ok=True)
                    cache_path.write_bytes(skin_bytes)
                except Exception as cache_err:
                    print(f"[Allio Avatar] Aviso guardando skin offline en caché: {cache_err}")
                print(f"[Allio Avatar] Skin offline descargada para {username}")
        except Exception as ensure_err:
            print(f"[Allio Avatar] Error asegurando skin offline: {ensure_err}")

    def _download_mojang_skin(self, username: str) -> Optional[bytes]:
        """Descarga la skin oficial de Mojang para un username dado."""
        try:
            if not username:
                return None

            profile_resp = requests.get(
                f"https://api.mojang.com/users/profiles/minecraft/{urllib.parse.quote(username)}",
                timeout=10,
            )
            if profile_resp.status_code != 200:
                return None

            profile_data = profile_resp.json()
            uuid_val = profile_data.get('id')
            if not uuid_val:
                return None

            textures_resp = requests.get(
                f"https://sessionserver.mojang.com/session/minecraft/profile/{uuid_val}",
                timeout=10,
            )
            if textures_resp.status_code != 200:
                return None

            textures_data = textures_resp.json()
            properties = textures_data.get('properties') or []
            skin_url = None
            for prop in properties:
                if prop.get('name') == 'textures' and prop.get('value'):
                    try:
                        decoded = base64.b64decode(prop['value']).decode('utf-8')
                        payload = json.loads(decoded)
                        skin_url = payload.get('textures', {}).get('SKIN', {}).get('url')
                        if skin_url:
                            break
                    except Exception as decode_err:
                        print(f"[Allio Avatar] Error decodificando texturas: {decode_err}")

            if not skin_url:
                return None

            skin_resp = requests.get(skin_url, timeout=15)
            if skin_resp.status_code == 200 and len(skin_resp.content) > 600:
                return skin_resp.content

        except Exception as skin_err:
            print(f"[Allio Avatar] Error descargando skin de Mojang: {skin_err}")

        return None

    def find_local_bedrock_skin (self ,gamertag :str )->Optional [QPixmap ]:
        """Busca skins locales de Minecraft Java Edition"""
        try :
            # Ruta de Minecraft Java Edition
            minecraft_java_path = Path(os.getenv("APPDATA", "")) / ".minecraft"

            if not minecraft_java_path.exists():
                print(f"[Allio Avatar] Minecraft Java no encontrado en: {minecraft_java_path}")
                return None

            print(f"[Allio Avatar] Buscando skins en Minecraft Java: {minecraft_java_path}")

            # Buscar en carpetas donde podrían estar las skins de Java
            skin_folders = [
                minecraft_java_path / "assets" / "skins",
                minecraft_java_path / "skins",
                minecraft_java_path / "textures" / "entity" / "player",
                minecraft_java_path / "versions" / "skins"
            ]

            for folder in skin_folders:
                if folder.exists():
                    print(f"[Allio Avatar] Buscando skins específicas en: {folder}")
                    skin = self.search_skin_files(folder, gamertag)
                    if skin:
                        return skin

            # También buscar en caché local de skins descargadas
            cache_folders = [
                minecraft_java_path / "assets" / "minecraft" / "textures" / "entity" / "player",
                Path(os.getenv("LOCALAPPDATA", "")) / "AllioClient" / "skins",
                Path(os.getenv("TEMP", "")) / "minecraft_skins"
            ]

            for cache_folder in cache_folders:
                if cache_folder.exists():
                    skin = self.search_skin_files(cache_folder, gamertag)
                    if skin:
                        return skin

            print("[Allio Avatar] No se encontraron skins locales específicas del jugador en Minecraft Java")
            return None

        except Exception as e:
            print(f"[Allio Avatar] Error buscando skins locales: {e}")
            return None 

    def search_skin_files (self ,folder :Path ,gamertag :str )->Optional [QPixmap ]:
        """Busca archivos de skin en una carpeta específica"""
        try :

            exclude_patterns =[
            'smoke','fire','water','lava','particle','effect','terrain',
            'item','block','mob','entity','gui','ui','font','icon'
            ]


            for file_path in folder .rglob ("*.png"):
                try :
                    file_name_lower =file_path .name .lower ()


                    if any (pattern in file_name_lower for pattern in exclude_patterns ):
                        continue 


                    if gamertag .lower ()in file_name_lower :
                        pm =QPixmap (str (file_path ))
                        if not pm .isNull ()and pm .width ()>=32 and pm .height ()>=32 :
                            print (f"[Allio Avatar] OK Skin encontrado por nombre: {file_path}")
                            return pm 
                except Exception :
                    continue 


            skin_patterns =['skin','player','character','avatar','steve','alex']
            for file_path in folder .rglob ("*.png"):
                try :
                    file_name_lower =file_path .name .lower ()


                    if any (pattern in file_name_lower for pattern in exclude_patterns ):
                        continue 


                    if any (pattern in file_name_lower for pattern in skin_patterns ):

                        if gamertag .lower ()not in file_name_lower and gamertag .lower ()not in str (file_path ).lower ():
                            continue 
                        pm =QPixmap (str (file_path ))
                        if not pm .isNull ():

                            if (pm .width ()==64 and pm .height ()in [32 ,64 ])or (pm .width ()==128 and pm .height ()in [64 ,128 ]):
                                print (f"[Allio Avatar] OK Skin encontrado por patrón y nombre: {file_path} ({pm.width()}x{pm.height()})")
                                return pm 
                except Exception :
                    continue 


            for file_path in folder .rglob ("*.png"):
                try :
                    file_name_lower =file_path .name .lower ()


                    if any (pattern in file_name_lower for pattern in exclude_patterns ):
                        continue 


                    if any (part in str (file_path ).lower ()for part in ['texture','particle','effect','ui','gui']):
                        continue 


                    if gamertag .lower ()not in file_name_lower and gamertag .lower ()not in str (file_path ).lower ():
                        continue 
                    pm =QPixmap (str (file_path ))
                    if not pm .isNull ():

                        if pm .width ()==64 and pm .height ()==64 :
                            print (f"[Allio Avatar] OK Posible skin encontrado por nombre: {file_path} ({pm.width()}x{pm.height()})")
                            return pm 
                except Exception :
                    continue 

        except Exception as e :
            print (f"[Allio Avatar] Error buscando en {folder}: {e}")

        return None 

    def _init_discord_rpc(self):
        """Inicializa Discord Rich Presence en un hilo separado"""
        try:
            if self.discord_rpc.connect():
                # Establecer estado inicial
                username = getattr(self, '_username', None)
                gamertag = self._memory_config.get('gamertag', '')
                display_name = username or gamertag or None
                self.discord_rpc.set_idle(display_name)
        except Exception as e:
            print(f"[Discord RPC] Error en inicialización: {e}")

    def set_profile_avatar (self ,face :QPixmap ):
        print (f"[Allio Avatar] Aplicando avatar: {face.width()}x{face.height()}")
        if hasattr (self ,'btn_profile'):
            self .btn_profile .setIconSize (face .size ())
            self .btn_profile .setIcon (QIcon (face ))
            if hasattr (self ,'_username')and self ._username !="Sin sesión":
                print (f"[Allio Avatar] Ocultando texto, mostrando solo icono para {self._username}")
                self .btn_profile .setText ("")
            else :
                print ("[Allio Avatar] Manteniendo texto en botón")

    def _on_avatar_status (self ,msg :str ,ok :bool ):
        print (f"[Allio Avatar] Estado: {msg} (éxito: {ok})")
        if not ok :
            print ("[Allio Avatar] Mostrando mensaje de error al usuario")

    def download_avatar (self ,gamertag :str )->Optional [QPixmap ]:
        headers ={
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept":"image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
        "Accept-Language":"en-US,en;q=0.9",
        "Referer":"https://minecraft.net/"
        }

        custom_skin_found = None
        
        for url in self .fetch_avatar_urls (gamertag ):
            try :
                req =urllib .request .Request (url ,headers =headers )
                # Usar timeout más corto para APIs que pueden fallar
                timeout = 3 if 'crafatar.com' in url else 6
                
                with urllib .request .urlopen (req ,timeout =timeout )as r :
                    data =r .read ()

                if len (data )<200 :
                    print (f"[Allio Avatar] Datos insuficientes desde {url} ({len(data)} bytes)")
                    continue 

                pm =QPixmap ()
                if not pm .loadFromData (data ):
                    print (f"[Allio Avatar] Falló cargar datos desde {url}")
                    continue 

                if pm .width ()<16 or pm .height ()<16 :
                    print (f"[Allio Avatar] ✗ {url} - {pm.width()}x{pm.height()} (demasiado pequeña)")
                    continue 

                print (f"[Allio Avatar] OK {url} - {pm.width()}x{pm.height()}")

                # Priorizar APIs de Minecraft Java
                lower =url .lower ()
                if any (token in lower for token in ("visage.surgeplay.com","ashcon.app","minotar.net","mineskin.eu","cravatar.eu")):
                    # Verificar si es una skin por defecto (Steve/Alex)
                    if self.is_default_skin(data):
                        print (f"[Allio Avatar] AVISO {url} devolvió skin por defecto (Steve/Alex)")
                        # Continuar buscando, pero guardar como fallback
                        if custom_skin_found is None:
                            custom_skin_found = pm
                        continue
                    else:
                        print (f"[Allio Avatar] OK Usando skin personalizada de Minecraft Java desde {url}")
                        return pm 

                # mc-heads.net y crafatar.com pueden devolver defaults frecuentemente
                if any (token in lower for token in ("mc-heads.net","crafatar.com")):
                    if self.is_default_skin(data):
                        print (f"[Allio Avatar] AVISO {url} devolvió skin por defecto")
                        continue
                    else:
                        print (f"[Allio Avatar] OK Skin personalizada encontrada desde {url}")
                        return pm

                # Procesar skins de Minecraft (extraer cara si es necesario)
                if pm .width ()>=64 and pm .height ()>=64 :
                    face =self .extract_java_face (pm )
                    if face :
                        print (f"[Allio Avatar] OK Cara extraída de skin de Minecraft Java")
                        return face 

                # Xbox Live como fallback
                if "xboxlive.com"in url .lower ():
                    print (f"[Allio Avatar] OK Usando avatar de Xbox Live como fallback")
                    return pm 

                # Otros casos válidos
                return pm 

            except Exception as ex :
                print (f"[Allio Avatar] ✗ {url}: {ex}")
                continue 

        # Si encontramos alguna skin por defecto pero no personalizada, usarla
        if custom_skin_found is not None:
            print (f"[Allio Avatar] INFO Usando skin por defecto como último recurso")
            return custom_skin_found

        print (f"[Allio Avatar] No se encontró avatar válido para {gamertag}")
        return None 

    def extract_java_face (self ,skin_pm :QPixmap )->Optional [QPixmap ]:
        if skin_pm .width ()<32 or skin_pm .height ()<32 :
            return None 
        base =skin_pm .copy (8 ,8 ,8 ,8 )
        if skin_pm .width ()>=48 :
            overlay =skin_pm .copy (40 ,8 ,8 ,8 )
            painter =QPainter (base )
            painter .setCompositionMode (QPainter .CompositionMode .CompositionMode_SourceOver )
            painter .drawPixmap (0 ,0 ,overlay )
            painter .end ()
        return base .scaled (64 ,64 ,Qt .AspectRatioMode .IgnoreAspectRatio ,Qt .TransformationMode .SmoothTransformation )

    def circularize (self ,pm :QPixmap ,size :int )->QPixmap :
        if pm .isNull ()or pm .width ()<8 or pm .height ()<8 :
            print (f"[Allio Avatar] Pixmap inválido or muy pequeño: {pm.width()}x{pm.height()}")
            return self .build_placeholder_avatar ("?")

        scaled =pm .scaled (size ,size ,Qt .AspectRatioMode .KeepAspectRatioByExpanding ,Qt .TransformationMode .SmoothTransformation )
        out_pm =QPixmap (size ,size )
        out_pm .fill (Qt .GlobalColor .transparent )
        painter =QPainter (out_pm )
        painter .setRenderHint (QPainter .RenderHint .Antialiasing )
        path =QPainterPath ()
        path .addEllipse (0 ,0 ,size ,size )
        painter .setClipPath (path )
        dx =(scaled .width ()-size )//2 
        dy =(scaled .height ()-size )//2 
        painter .drawPixmap (-dx ,-dy ,scaled )
        painter .end ()

        print (f"[Allio Avatar] Avatar circular creado: {out_pm.width()}x{out_pm.height()}")
        return out_pm 

    def build_placeholder_avatar (self ,text :str )->QPixmap :
        size =48 
        pm =QPixmap (size ,size )
        pm .fill (Qt .GlobalColor .transparent )
        painter =QPainter (pm )
        painter .setRenderHint (QPainter .RenderHint .Antialiasing )

        painter .setBrush (QColor (107 ,174 ,214 ))
        painter .setPen (Qt .PenStyle .NoPen )
        painter .drawEllipse (0 ,0 ,size ,size )

        painter .setPen (QPen (QColor (255 ,255 ,255 ,100 ),1 ))
        painter .setBrush (Qt .BrushStyle .NoBrush )
        painter .drawEllipse (1 ,1 ,size -2 ,size -2 )

        painter .setPen (QColor (255 ,255 ,255 ))
        painter .setFont (QFont ("Segoe UI",20 ,QFont .Weight .Bold ))
        letter =(text [:1 ]or "?").upper ()
        rect =pm .rect ()
        painter .drawText (rect ,Qt .AlignmentFlag .AlignCenter ,letter )
        painter .end ()

        print (f"[Allio Avatar] Placeholder creado para '{text}': {pm.width()}x{pm.height()}")
        return pm 

    def apply_style (self ):
        self .setStyleSheet ("""
    QWidget#mainBg { background:#ffffff; border-radius:22px; }
    QWidget#titleBar { background:transparent; }
        QLabel#titleIcon { border-radius:6px; }
        QLabel#titleLabel { color:#f2f2f2; font:600 19px "Segoe UI"; letter-spacing:.6px; }

        QWidget#titleBar QPushButton#titleBtn,
        QWidget#titleBar QPushButton#closeBtn {
            background:rgba(0,0,0,0.06);
            border:1px solid rgba(0,0,0,0.08);
            border-radius:6px;
            font:500 15px "Segoe UI";
            color:#222222;
            padding:0;
        }
        QWidget#titleBar QPushButton#titleBtn:hover { background:rgba(0,0,0,0.10); }
        QWidget#titleBar QPushButton#titleBtn:pressed { background:rgba(0,0,0,0.14); }
        QWidget#titleBar QPushButton#closeBtn:hover { background:#d84343; border:1px solid #d84343; color:#fff; }
        QWidget#titleBar QPushButton#closeBtn:pressed { background:#a82626; border:1px solid #a82626; }

        QWidget#actionBar {
            background:rgba(255,255,255,0.06);
            border:1px solid rgba(255,255,255,0.35);
            border-radius:26px;
            padding:0;
        }
        QWidget#actionBar QPushButton {
            background:transparent;
            border:none;
            color:#f0f0f0;
            font:600 18px "Segoe UI";
            padding:14px 34px;
        }
        QWidget#actionBar QPushButton:hover { background:rgba(255,255,255,0.08); }
        QWidget#actionBar QPushButton:pressed { background:rgba(255,255,255,0.16); }
        QWidget#actionBar QPushButton + QPushButton { border-left:1px solid rgba(255,255,255,0.35); }
        QWidget#actionBar QPushButton#segBtnLeft { border-top-left-radius:26px; border-bottom-left-radius:26px; }
        QWidget#actionBar QPushButton#segBtnRight { border-top-right-radius:26px; border-bottom-right-radius:26px; }
        """)

    def closeEvent(self, event):
        """Maneja el evento de cierre de la ventana"""
        try:
            # Desconectar Discord RPC al cerrar
            if hasattr(self, 'discord_rpc'):
                self.discord_rpc.disconnect()
        except Exception as e:
            print(f"[Discord RPC] Error al desconectar en closeEvent: {e}")
        
        # Llamar al closeEvent original
        super().closeEvent(event)

# Login dialog removed per user request

class PacksDialog (QDialog ):
    def __init__ (self ,parent =None ):
        super ().__init__ (parent )
        self .setWindowTitle ("Addons / Texture Packs")
        self .setModal (True )

        self .setStyleSheet ("""
            QDialog { background: #2d2d30; border-radius: 12px; }
            QLabel { background: transparent; color: #eee; }
            QPushButton {
                background: #107c10;
                color: #fff;
                font: 600 14px 'Segoe UI';
                padding: 10px 20px;
                border: none;
                border-radius: 8px;
            }
            QPushButton:hover { background: #0e6b0e; }
            QPushButton:pressed { background: #0c5a0c; }
        """)

        lay =QVBoxLayout (self )
        lay .setContentsMargins (25 ,20 ,25 ,20 )
        lay .setSpacing (12 )

        self .label =QLabel ("Texture Pack:")
        self .label .setStyleSheet ("color:#eee;font:600 16px 'Segoe UI';")
        self .preview =QLabel ()
        self .preview .setFixedSize (260 ,140 )

        preview_1_path =resource_path ("1.png")
        if os .path .exists (preview_1_path ):
            pm =QPixmap (preview_1_path ).scaled (self .preview .size (),Qt .AspectRatioMode .KeepAspectRatio ,Qt .TransformationMode .SmoothTransformation )
            self .preview .setPixmap (pm )
        else :
            self .preview .setText ("1.png no encontrado")
            self .preview .setStyleSheet ("color:#aaa;")
        self .preview .setAlignment (Qt .AlignmentFlag .AlignCenter )
        self .import_btn =QPushButton ("Importar Texture Pack a Minecraft")
        self .import_btn .clicked .connect (self .import_pack )
        self .result =QLabel ("")
        self .result .setStyleSheet ("color:#8bc34a;")
        lay .addWidget (self .label )
        lay .addWidget (self .preview )
        lay .addWidget (self .import_btn )
        lay .addWidget (self .result )

        self ._pack_source =Path (resource_path ("BackroomsMenu"))
        manifest_path =self ._pack_source /"manifest.json"
        pack_name ="BackroomsMenu"
        desc =""
        if manifest_path .exists ():
            try :
                data =json .load (open (manifest_path ,"r",encoding ="utf-8"))
                pack_name =data .get ("header",{}).get ("name",pack_name )
                desc =data .get ("header",{}).get ("description","")
            except Exception :
                pass 
        self .label .setText (f"Texture Pack: {pack_name}\n{desc}")

        preview_file =None 
        pack_icon_path =resource_path ("BackroomsMenu/pack_icon.png")
        preview_1_path =resource_path ("1.png")

        for cand in [pack_icon_path ,preview_1_path ]:
            if os .path .exists (cand ):
                preview_file =cand 
                break 
        if preview_file :
            pm =QPixmap (preview_file ).scaled (self .preview .size (),Qt .AspectRatioMode .KeepAspectRatio ,Qt .TransformationMode .SmoothTransformation )
            self .preview .setPixmap (pm )
        else :
            self .preview .setText ("Icono no encontrado")
            self .preview .setStyleSheet ("color:#aaa;")
        self .preview .setAlignment (Qt .AlignmentFlag .AlignCenter )

    def import_pack (self ):
        pack_path =Path (resource_path ("BackroomsMenu"))
        ok ,msg =import_texture_pack (pack_path )
        self .result .setText (msg )
        self .result .setStyleSheet ("color:#8bc34a;"if ok else "color:#ef5350;")

def import_texture_pack (source_dir :Path ):
    if not isinstance (source_dir ,Path ):
        source_dir =Path (source_dir )
    if not source_dir .exists ()or not source_dir .is_dir ():
        return False ,f"No existe carpeta '{source_dir}'."
    base =Path (os .getenv ("LOCALAPPDATA",""))/"Packages"/"Microsoft.MinecraftUWP_8wekyb3d8bbwe"/"LocalState"/"games"/"com.mojang"/"resource_packs"
    try :
        base .mkdir (parents =True ,exist_ok =True )
    except Exception as e :
        return False ,f"Error creando resource_packs:\n{e}"
    target =base /source_dir .name 
    if target .exists ():
        return True ,f"Pack '{source_dir.name}' ya importado."
    try :
        def copy_tree (src :Path ,dst :Path ):
            dst .mkdir (exist_ok =True )
            for item in src .iterdir ():
                dpath =dst /item .name 
                if item .is_dir ():
                    copy_tree (item ,dpath )
                else :
                    with open (item ,"rb")as fsrc ,open (dpath ,"wb")as fdst :
                        fdst .write (fsrc .read ())
        copy_tree (source_dir ,target )
        pack_icon_target =target /"pack_icon.png"
        if not pack_icon_target .exists ():
            preview_1_path =resource_path ("1.png")
            if os .path .exists (preview_1_path ):
                with open (preview_1_path ,"rb")as s ,open (pack_icon_target ,"wb")as d :
                    d .write (s .read ())
    except Exception as e :
        return False ,f"Error copiando pack: {e}"
    return True ,f"Pack '{source_dir.name}' importado."

def import_texture_pack (source_dir :Path ):
    try :
        pack_dir =get_minecraft_java_resource_packs_path ()
        if not pack_dir :
            return False ,"No se pudo encontrar el directorio de resource packs"

        pack_name =source_dir .name 
        target =Path (pack_dir )/pack_name 

        if target .exists ():
            import shutil 
            shutil .rmtree (target )

        import shutil 
        shutil .copytree (source_dir ,target )


        try :
            preview_paths =[
            source_dir /"pack_icon.png",
            source_dir /"textures"/"ui"/"loading_background.png"
            ]
            available_preview =None 
            for p in preview_paths :
                if p .exists ():
                    available_preview =p 
                    break 

            if available_preview :
                pack_icon_target =target /"pack_icon.png"
                with open (available_preview ,"rb")as s ,open (pack_icon_target ,"wb")as d :
                    d .write (s .read ())
        except Exception :
            pass 

        try :
            preview_1_path =source_dir /"pack_icon.png"
            if preview_1_path .exists ():
                pack_icon_target =target /"pack_icon.png"
                with open (preview_1_path ,"rb")as s ,open (pack_icon_target ,"wb")as d :
                    d .write (s .read ())
        except Exception:
            pass
    except Exception as e :
        return False ,f"Error copiando pack: {e}"
    return True ,f"Pack '{source_dir.name}' importado."


class LoadingWidget (QWidget ):
    checkFinished =pyqtSignal (bool ,object ,str )

    def __init__ (self ,parent =None ):
        super ().__init__ (parent )
        self .setObjectName ("loadingBg")
        self .bg_path =resource_path ("iniciofondo.png")
        self .bg =QPixmap (self .bg_path )if os .path .exists (self .bg_path )else None 


        lay =QVBoxLayout (self )

        lay .setContentsMargins (0 ,0 ,0 ,14 )
        lay .setSpacing (0 )


        try:
            if not globals().get('USE_NATIVE_TITLEBAR', False):
                self.titleBar = TitleBar(self)
                try:
                    self.titleBar.setStyleSheet("""
                        QWidget#titleBar { background: #000; border-top-left-radius: 0px; border-top-right-radius: 0px; }
                        QLabel#titleLabel { color:#f2f2f2; font:600 19px "Segoe UI"; }
                        QLabel#titleIcon { border-radius:6px; }
                        QWidget#titleBar QPushButton#titleBtn,
                        QWidget#titleBar QPushButton#closeBtn {
                            background:rgba(255,255,255,0.08);
                            border:1px solid rgba(255,255,255,0.12);
                        }
                    """)
                except Exception:
                    pass
                lay.addWidget(self.titleBar)
                main_window = parent if parent is not None else self.window()
                if main_window is not None:
                    try:
                        self.titleBar.minimizeRequested.connect(lambda: main_window.showMinimized() if hasattr(main_window, 'showMinimized') else None)
                        self.titleBar.closeRequested.connect(lambda: main_window.close() if hasattr(main_window, 'close') else None)
                        self.titleBar.maximizeRequested.connect(lambda: main_window.toggle_max_restore() if hasattr(main_window, 'toggle_max_restore') else None)
                    except Exception:
                        pass
            else:
                self.titleBar = None
        except Exception:
            self.titleBar = None

        lay .addStretch ()

        self .icon_label =QLabel ()
        self .icon_label .setAlignment (Qt .AlignmentFlag .AlignCenter )

        lay .addWidget (self .icon_label ,alignment =Qt .AlignmentFlag .AlignCenter )
        lay .addStretch ()


        self ._angle =0.0 
        self ._timer =QTimer (self )
        self ._timer .setInterval (30 )
        self ._timer .timeout .connect (self ._on_timer )


        self .setStyleSheet ("""
            QWidget#loadingBg { background:transparent; }
            QLabel { color: #fff; }
        """)

    def paintEvent (self ,event ):
        p =QPainter (self )
        p .setRenderHint (QPainter .RenderHint .Antialiasing )

        if self .bg :
            scaled =self .bg .scaled (self .size (),Qt .AspectRatioMode .KeepAspectRatioByExpanding ,Qt .TransformationMode .SmoothTransformation )
            x =(self .width ()-scaled .width ())//2 
            y =(self .height ()-scaled .height ())//2 
            p .drawPixmap (x ,y ,scaled )
        else :
            p .fillRect (self .rect (),QColor (0 ,0 ,0 ))


        try :
            center =self .rect ().center ()
            p .save ()
            p .translate (center )

            radius =min (self .width (),self .height ())*0.09 
            if radius <12 :
                radius =12 
            r =int (radius )

            pen_bg =QPen (QColor (255 ,255 ,255 ,30 ))
            pen_bg .setWidth (max (4 ,r //6 ))
            pen_bg .setCapStyle (Qt .PenCapStyle .RoundCap )
            p .setPen (pen_bg )
            p .drawEllipse (-r ,-r ,r *2 ,r *2 )


            pen =QPen (QColor ("#cd1955"))
            pen .setWidth (max (6 ,r //4 ))
            pen .setCapStyle (Qt .PenCapStyle .RoundCap )
            p .setPen (pen )
            start_angle =int (self ._angle *16 )
            span_angle =int (300 *16 )
            p .drawArc (-r ,-r ,r *2 ,r *2 ,start_angle ,-span_angle )
            p .restore ()
        except Exception :
            pass 

        super ().paintEvent (event )

    def start_check (self ,gamertag :str ):

        try :
            print (f"[LoadingWidget] start_check: inicio para '{gamertag}' (thread={threading.current_thread().name})")
            print(f"[LoadingWidget] start_check: timer isActive before start = {self._timer.isActive()}")
            if not self ._timer .isActive ():
                self ._angle =0.0 
                self ._timer .start ()
                print(f"[LoadingWidget] start_check: timer started, isActive now = {self._timer.isActive()}")
        except Exception :
            pass 
        threading .Thread (target =self ._worker ,args =(gamertag ,),daemon =True ).start ()

    def stop (self ):
        try :
            if self ._timer .isActive ():
                self ._timer .stop ()
        except Exception :
            pass 

    def _on_timer (self ):
        self ._angle =(self ._angle +6 )%360 
        try :
            self .update ()
        except Exception :
            pass 

    def _worker (self ,gamertag :str ):
        print (f"[LoadingWidget] _worker: inicio para '{gamertag}' (thread={threading.current_thread().name})")
        result_pm =None 
        try :
            parent =self .parent ()
            if parent and hasattr (parent ,"find_local_bedrock_skin"):
                result_pm =parent .find_local_bedrock_skin (gamertag )
            if result_pm is None :
                parent =self .parent ()
                if parent and hasattr (parent ,"download_avatar"):
                    result_pm =parent .download_avatar (gamertag )
        except Exception as e :
            print (f"[LoadingWidget] Error durante verificación: {e}")
            result_pm =None 

        ok =result_pm is not None 
        face =None 
        try :
            parent =self .parent ()
            if ok and parent and hasattr (parent ,"circularize"):
                face =parent .circularize (result_pm ,48 )
        except Exception :
            face =None 
        try:
            print(f"[LoadingWidget] _worker: emitting checkFinished ok={ok}, face={'yes' if face else 'no'}, gamertag={gamertag}")
        except Exception:
            pass
        self .checkFinished .emit (ok ,face ,gamertag )
        try:
            print(f"[LoadingWidget] _worker: emitted checkFinished for '{gamertag}'")
        except Exception:
            pass


class InstancesWidget (QWidget ):
    def __init__ (self ,parent =None ):
        super ().__init__ (parent )
        self .setObjectName ("instancesBg")

        self .setStyleSheet ("QWidget#instancesBg { background-color: #000000; border-radius:18px; }")

        try :
            self .setAttribute (Qt .WidgetAttribute .WA_StyledBackground ,True )
        except Exception :
            pass 
        try :
            self .setAutoFillBackground (True )
        except Exception :
            pass 


        try:
            if not globals().get('USE_NATIVE_TITLEBAR', False):
                self .titleBar = TitleBar(self)
                main_window = parent if parent is not None else self.window()
                if main_window is not None:
                    try:
                        self .titleBar .minimizeRequested .connect (lambda :main_window .showMinimized ()if hasattr (main_window ,'showMinimized')else None )
                        self .titleBar .closeRequested .connect (lambda :main_window .close ()if hasattr (main_window ,'close')else None )
                        self .titleBar .maximizeRequested .connect (lambda :main_window .toggle_max_restore ()if hasattr (main_window ,'toggle_max_restore')else None )
                    except Exception:
                        pass
            else:
                self .titleBar = None
        except Exception:
            self .titleBar = None


        lay =QVBoxLayout (self )
        lay .setContentsMargins (0 ,0 ,0 ,0 )
        lay .setSpacing (0 )
        if getattr(self, 'titleBar', None) is not None:
            lay.addWidget(self.titleBar, 0)


        inner =QWidget ()
        inner_l =QVBoxLayout (inner )
        # increase top margin to provide breathing room under the title
        inner_l .setContentsMargins (30 ,48 ,30 ,18 )
        inner_l .setSpacing (20 )
        # expose inner layout so we can adjust top margin dynamically without shrinking the black background
        try:
            self.inner_l = inner_l
            self.base_top_margin = 48
        except Exception:
            pass


        top =QWidget ()

        th =QHBoxLayout (top )
        th .setContentsMargins (0 ,0 ,0 ,0 )

        th .addStretch ()
        inner_l .addWidget (top )


        title =QLabel ()
        title .setText ('<span style="font-weight:800; font-size:48px; color:#fff;">Available </span>'
        '<span style="font-weight:800; font-size:48px; color:#ff8c3b;">Instances</span>')
        title .setAlignment (Qt .AlignmentFlag .AlignLeft )
        inner_l .addWidget (title )


        thumbs =QWidget ()
        # ensure the thumbs area reserves vertical space so thumbnails are centered lower
        thumbs.setMinimumHeight(220)
        hl =QHBoxLayout (thumbs )
        hl .setContentsMargins (40 ,40 ,40 ,40 )
        hl .setSpacing (80 )

        def make_thumb (img_path ,glow_color =QColor (255 ,140 ,59 ),target_bg :str =None ,inst_index :int |None =None ):
            btn =QPushButton ()
            w ,h =320 ,160 
            btn .setFixedSize (w ,h )
            btn .setFlat (True )
            btn .setCursor (Qt .CursorShape .PointingHandCursor )
            btn .setStyleSheet ("background: transparent; border: none;")
            if os .path .exists (img_path ):
                pm =QPixmap (img_path ).scaled (QSize (w ,h ),Qt .AspectRatioMode .KeepAspectRatioByExpanding ,Qt .TransformationMode .SmoothTransformation )
                btn .setIcon (QIcon (pm ))
                btn .setIconSize (QSize (w ,h ))
            else :
                btn .setText ("no image")
                btn .setStyleSheet ("background:#141414; color:#bbb; border-radius:8px;")

            eff =QGraphicsDropShadowEffect (btn )
            eff .setBlurRadius (48 )
            eff .setColor (glow_color )
            eff .setOffset (0 ,0 )
            btn .setGraphicsEffect (eff )


            def _on_click ():
                try :
                    main_win =parent if parent is not None else self .window ()
                    if main_win is not None and hasattr (main_win ,"mapWidget")and target_bg :
                        try :
                            main_win .mapWidget .set_background_image (target_bg )
                        except Exception :
                            pass 

                        try:
                            if inst_index is not None:
                                main_win.mapWidget.show_instance_button(inst_index, only_this=False)
                        except Exception:
                            pass

                        try :
                            if hasattr (main_win ,"switch_to_map"):
                                main_win .switch_to_map ()
                        except Exception :
                            pass 
                except Exception :
                    pass 
            btn .clicked .connect (_on_click )
            return btn 


        raw_thumb =make_thumb (resource_path ("fondoinstacia3.png"),QColor (255 ,140 ,59 ),target_bg ="fondoinstacia3.png",inst_index =1 )



        class BubbleWidget (QWidget ):
            def __init__ (self ,text :str ,parent =None ):
                super ().__init__ (parent )
                self .label =QLabel (text ,self )
                self .label .setStyleSheet ("color: white; font:700 13px 'Segoe UI'; background: transparent;")
                self .label .setAlignment (Qt .AlignmentFlag .AlignCenter )
                self .setVisible (False )

            def sizeHint (self ):
                return QSize (150 ,40 )

            def resizeEvent (self ,e ):
                self .label .setGeometry (10 ,6 ,max (1 ,self .width ()-20 ),max (1 ,self .height ()-12 ))
                super ().resizeEvent (e )

            def paintEvent (self ,e ):
                p =QPainter (self )
                p .setRenderHint (QPainter .RenderHint .Antialiasing )
                w =self .width ()
                h =self .height ()

                tail_offset =16.0 
                rect =QRectF (tail_offset ,0.0 ,float (w )-tail_offset ,float (h ))
                path =QPainterPath ()

                path .addRoundedRect (rect ,10.0 ,10.0 )

                tri =QPainterPath ()
                ty =float (h )/2.0 
                tail_w =tail_offset 
                tail_h =min (22.0 ,float (h )*0.6 )

                tri .moveTo (tail_offset ,ty -tail_h /2.0 )
                tri .lineTo (0.0 ,ty )
                tri .lineTo (tail_offset ,ty +tail_h /2.0 )
                tri .closeSubpath ()
                path .addPath (tri )
                p .setPen (Qt .PenStyle .NoPen )
                p .setBrush (QColor (25 ,118 ,210 ))
                p .drawPath (path )
                super ().paintEvent (e )

        class HoverThumbWrapper (QWidget ):
            def __init__ (self ,raw_btn :QPushButton ):
                super ().__init__ ()
                self ._raw =raw_btn 

                self ._raw .setParent (self )

                try :
                    self ._raw .setFlat (True )
                except Exception :
                    pass 

                self ._bubble =BubbleWidget ("Hardcore",None )
                self ._bubble .setVisible (False )

                self .setFixedSize (self ._raw .size ())
                self ._raw .move (0 ,0 )
                self ._raw .show ()
                self ._orig_geom =self ._raw .geometry ()
                self ._zoom_factor =1.12 


                self ._raw .installEventFilter (self )

            def eventFilter (self ,watched ,event ):
                try :
                    if watched is self ._raw :
                        if event .type ()==QEvent .Type .Enter :
                            self ._on_enter ()
                            return False 
                        elif event .type ()==QEvent .Type .Leave :
                            self ._on_leave ()
                            return False 
                except Exception :
                    pass 
                return super ().eventFilter (watched ,event )

            def _on_enter (self ):
                try :
                    r =self ._raw .geometry ()
                    w =r .width ();h =r .height ()
                    nw =int (w *self ._zoom_factor );nh =int (h *self ._zoom_factor )
                    dx =(nw -w )//2 ;dy =(nh -h )//2 
                    target =QRect (r .x ()-dx ,r .y ()-dy ,nw ,nh )
                    anim =QPropertyAnimation (self ._raw ,b"geometry")
                    anim .setDuration (220 )
                    anim .setStartValue (r )
                    anim .setEndValue (target )
                    anim .setEasingCurve (QEasingCurve .Type .OutCubic )
                    anim .start ()
                    self ._anim =anim 

                    bw =150 ;bh =40 
                    margin =0 
                    top_win =self .window ()if self .window ()is not None else self .parentWidget ()
                    try :
                        self ._bubble .setParent (top_win )
                    except Exception :
                        pass 

                    wpos = self.mapTo(top_win, QPoint(0, 0))

                    # position the bubble centered below the thumbnail (prefer below)
                    bx = wpos.x() + (self.width() - bw) // 2
                    # move the bubble up a bit more: 16px overlap so it sits higher over the thumbnail
                    by = wpos.y() + self.height() - 74

                    win_w = top_win.width() if top_win is not None else 1920
                    win_h = top_win.height() if top_win is not None else 1080

                    # horizontal clamp
                    if bx < 8:
                        bx = 8
                    if bx + bw > win_w - 8:
                        bx = win_w - bw - 8

                    # if there's not enough space below, fallback to placing bubble above
                    if by + bh > win_h - 8:
                        # try placing above
                        # alternative above placement also moved 16px closer
                        alt_by = wpos.y() - bh - 74
                        if alt_by >= 8:
                            by = alt_by
                        else:
                            # final fallback: right-middle
                            by = wpos.y() + max(0, (self.height() - bh) // 2)
                            if by + bh > win_h - 8:
                                by = max(8, win_h - bh - 8)
                    self ._bubble .setGeometry (int (bx ),int (by ),int (bw ),int (bh ))
                    self ._bubble .setWindowOpacity (0.0 )
                    self ._bubble .show ()
                    b_anim =QPropertyAnimation (self ._bubble ,b"windowOpacity")
                    b_anim .setDuration (260 )
                    b_anim .setStartValue (0.0 )
                    b_anim .setEndValue (1.0 )
                    b_anim .setEasingCurve (QEasingCurve .Type .OutCubic )
                    b_anim .start ()
                    self ._bubble_anim =b_anim 
                except Exception :
                    pass 

            def _on_leave (self ):
                try :
                    r =self ._raw .geometry ()
                    orig =self ._orig_geom 
                    anim =QPropertyAnimation (self ._raw ,b"geometry")
                    anim .setDuration (200 )
                    anim .setStartValue (r )
                    anim .setEndValue (orig )
                    anim .setEasingCurve (QEasingCurve .Type .InCubic )
                    anim .start ()
                    self ._anim =anim 
                    try :
                        b_anim =QPropertyAnimation (self ._bubble ,b"windowOpacity")
                        b_anim .setDuration (200 )
                        b_anim .setStartValue (1.0 )
                        b_anim .setEndValue (0.0 )
                        b_anim .setEasingCurve (QEasingCurve .Type .InCubic )
                        def _hide ():
                            try :
                                self ._bubble .hide ()

                                try :
                                    self ._bubble .setParent (None )
                                except Exception :
                                    pass 
                            except Exception :
                                pass 
                        b_anim .finished .connect (_hide )
                        b_anim .start ()
                        self ._bubble_anim =b_anim 
                    except Exception :
                        pass 
                except Exception :
                    pass 


        wrapper =HoverThumbWrapper (raw_thumb )
        hl .addStretch ()
        hl .addWidget (wrapper )
        hl .addStretch ()

        inner_l .addWidget (thumbs )
        inner_l .addStretch ()


        lay .addWidget (inner ,1 )

        try :
            main_window = parent if parent is not None else self .window ()
            self ._owner =main_window 
            if main_window is not None :
                try :
                    main_window .installEventFilter (self )
                except Exception :
                    pass 

                try :
                    # position the overlay but leave the leftBar area visible
                    def _leftbar_width():
                        try:
                            if hasattr(main_window, 'mapWidget') and main_window.mapWidget is not None:
                                lb = main_window.mapWidget.findChild(QWidget, "leftBar")
                                if lb is not None:
                                    return lb.width()
                        except Exception:
                            pass
                        return 0

                    if main_window is not None:
                        try:
                            # fill the available main window area (respect titlebar)
                            try:
                                top_off = _computed_titlebar_height(main_window)
                            except Exception:
                                top_off = 44
                            # compute an extra vertical offset so the widget sits lower (avoid being 'por arriba')
                            try:
                                # proportional offset: 3% of window height, clamped between 12 and 64
                                extra_top = int(max(12, min(64, int(max(1, main_window.height()) * 0.03))))
                            except Exception:
                                extra_top = 32
                            try:
                                # raise the black overlay by a noticeable amount (proportional and clamped)
                                raise_px = int(max(60, min(240, int(max(1, main_window.height()) * 0.12))))
                            except Exception:
                                raise_px = 80
                            start_y = max(0, top_off - raise_px)
                            self.setGeometry(0, start_y, max(1, main_window.width()), max(1, main_window.height() - start_y))
                            try:
                                if getattr(self, 'inner_l', None) is not None:
                                    self.inner_l.setContentsMargins(30, self.base_top_margin + extra_top, 30, 18)
                            except Exception:
                                pass
                        except Exception:
                            try:
                                geom = main_window.geometry()
                                self.setGeometry(geom)
                            except Exception:
                                pass
                    else :
                        try:
                            top_off = _computed_titlebar_height(main_window)
                        except Exception:
                            top_off = 44
                        self .setGeometry (0 ,top_off ,max (1 ,main_window .width ()),max (1 ,main_window .height ()-top_off ))
                except Exception :
                    try :
                        self .setGeometry (0 ,0 ,max (1 ,self .width ()),max (1 ,self .height ()))
                    except Exception :
                        pass 
        except Exception :
            self ._owner =None 

        # Ensure instance buttons are visible after startup: some startup code may toggle
        # visibility later (based on config/bg). Force them visible shortly after init.
        try:
            from PyQt6.QtCore import QTimer
            def _ensure_buttons_visible():
                try:
                    for idx, b in enumerate(getattr(self, 'inst_buttons', [])):
                        try:
                            b.show()
                            b.setVisible(True)
                            if idx == 0:
                                try:
                                    b.setStyleSheet("background: transparent; border: 3px solid #3aa8ff; border-radius:8px;")
                                except Exception:
                                    pass
                            else:
                                try:
                                    b.setStyleSheet("background: transparent; border: none;")
                                except Exception:
                                    pass
                        except Exception:
                            pass
                except Exception:
                    pass
            QTimer.singleShot(120, _ensure_buttons_visible)
        except Exception:
            pass

    def paintEvent (self ,event ):
        p =QPainter (self )
        p .setRenderHint (QPainter .RenderHint .Antialiasing )
        if getattr (self ,'bg',None ):
            try :
                # apply a larger negative vertical offset so the background image sits higher
                bg_offset = -100  # raise background by 80 pixels; tweak this value if needed
                scaled =self .bg .scaled (self .size (),Qt .AspectRatioMode .KeepAspectRatioByExpanding ,Qt .TransformationMode .SmoothTransformation )
                x =(self .width ()-scaled .width ())//2 
                y =((self .height ()-scaled .height ())//2) + bg_offset
                p .drawPixmap (x ,y ,scaled )
            except Exception :
                p .fillRect (self .rect (),QColor (0 ,0 ,0 ))
        else :
            p .fillRect (self .rect (),QColor (0 ,0 ,0 ))
        super ().paintEvent (event )

        # note: InstancesWidget installs an event filter on the main window in __init__

    def eventFilter (self ,watched ,event ):

        try :
            main_window =self .parent ()if self .parent ()is not None else self .window ()
            if main_window is not None and watched is main_window :
                if event .type ()in (QEvent .Type .Resize ,QEvent .Type .Move ,QEvent .Type .WindowStateChange ):
                    try :
                        try:
                            # when main window resizes, fill the available window area
                            try:
                                top_off = _computed_titlebar_height(main_window)
                            except Exception:
                                top_off = 44
                            extra_top = 8
                            try:
                                raise_px = int(max(60, min(240, int(max(1, main_window.height()) * 0.12))))
                            except Exception:
                                raise_px = 80
                            start_y = max(0, top_off - raise_px)
                            self.setGeometry(0, start_y, max(1, main_window.width()), max(1, main_window.height() - start_y))
                            try:
                                if getattr(self, 'inner_l', None) is not None:
                                    self.inner_l.setContentsMargins(30, self.base_top_margin + extra_top, 30, 18)
                            except Exception:
                                pass
                        except Exception:
                            try:
                                geom = main_window.geometry()
                                self.setGeometry(geom)
                            except Exception:
                                pass
                    except Exception :
                        try :
                            self .setGeometry (0 ,0 ,max (1 ,main_window .width ()),max (1 ,main_window .height ()))
                        except Exception :
                            pass 
        except Exception :
            pass 
        return super ().eventFilter (watched ,event )

    def showEvent(self, event):
        """When the map widget is shown, ensure instance buttons are visible and styled."""
        try:
            super().showEvent(event)
        except Exception:
            pass
        # also ensure geometry is recalculated when shown (fix race conditions)
        try:
            main_window = self.parent() if self.parent() is not None else self.window()
            if main_window is not None:
                try:
                    top_off = _computed_titlebar_height(main_window)
                except Exception:
                    top_off = 44
                try:
                    # proportional offset: 3% of window height, clamped between 12 and 64
                    extra_top = int(max(12, min(64, int(max(1, main_window.height()) * 0.03))))
                except Exception:
                    extra_top = 32
                try:
                    try:
                        raise_px = int(max(60, min(240, int(max(1, main_window.height()) * 0.12))))
                    except Exception:
                        raise_px = 80
                    start_y = max(0, top_off - raise_px)
                    self.setGeometry(0, start_y, max(1, main_window.width()), max(1, main_window.height() - start_y))
                    try:
                        if getattr(self, 'inner_l', None) is not None:
                            self.inner_l.setContentsMargins(30, self.base_top_margin + extra_top, 30, 18)
                    except Exception:
                        pass
                except Exception:
                    pass
        except Exception:
            pass
        try:
            if hasattr(self, 'inst_buttons'):
                for i, b in enumerate(self.inst_buttons):
                    try:
                        b.show()
                        b.setVisible(True)
                        b.raise_()
                        if i == 0:
                            try:
                                b.setStyleSheet("background: transparent; border: 3px solid #3aa8ff; border-radius:8px;")
                            except Exception:
                                pass
                        else:
                            try:
                                b.setStyleSheet("background: transparent; border: none;")
                            except Exception:
                                pass
                    except Exception:
                        pass
        except Exception:
            pass

class UnauthorizedWidget (QWidget ):
    """Pantalla simple que muestra mensaje de 'Unauthorized' y botón 'Log Out'.
    Se muestra cuando un usuario ha iniciado sesión pero no está autorizado (no figura
    en la lista de instancias del config)."""
    def __init__ (self ,parent =None ,gamertag :str ="",owner_window =None ):
        super ().__init__ (parent if parent is not None else None )
        self .setObjectName ("unauthBg")
        try :
            self .setAttribute (Qt .WidgetAttribute .WA_StyledBackground ,True )
        except Exception :
            pass 


        self .bg_path =resource_path ("iniciofondo.png")
        self .bg =QPixmap (self .bg_path )if os .path .exists (self .bg_path )else None 


        lay =QVBoxLayout (self )
        lay .setContentsMargins (0 ,0 ,0 ,0 )
        lay .setSpacing (0 )


        try:
            if not globals().get('USE_NATIVE_TITLEBAR', False):
                self.titleBar = TitleBar(self)
            else:
                self.titleBar = None
        except Exception:
            self.titleBar = None

        if getattr(self, 'titleBar', None) is not None:
            try:
                lay.addWidget(self.titleBar, 0)
            except Exception:
                pass
            main_window = parent if parent is not None else self.window()
            if main_window is not None:
                try:
                    self.titleBar.minimizeRequested.connect(lambda: main_window.showMinimized() if hasattr(main_window, 'showMinimized') else None)
                    self.titleBar.closeRequested.connect(lambda: main_window.close() if hasattr(main_window, 'close') else None)
                    self.titleBar.maximizeRequested.connect(lambda: main_window.toggle_max_restore() if hasattr(main_window, 'toggle_max_restore') else None)
                except Exception:
                    pass


        inner =QWidget ()
        inner_l =QVBoxLayout (inner )
        inner_l .setContentsMargins (40 ,40 ,40 ,40 )
        inner_l .setSpacing (20 )

        title =QLabel ()
        title .setText ('<span style="font-weight:800; font-size:56px; color:#e91e63;">Unauthorized</span>')
        title .setAlignment (Qt .AlignmentFlag .AlignLeft )
        inner_l .addWidget (title )

        body =QLabel ()
        body .setWordWrap (True )
        body .setText ("Membership to instances is restricted at this moment. If you are anticipating participation in an event, kindly provide your Minecraft username to the event organizer via the appropriate Discord channel.")
        body .setStyleSheet ("color:#e6e6e6; font:14px 'Segoe UI';")
        body .setAlignment (Qt .AlignmentFlag .AlignLeft )
        inner_l .addWidget (body )

        self .me_label =QLabel ()
        self .me_label .setText (f'You are currently logged in as “{gamertag}”.')
        self .me_label .setStyleSheet ("color:#f0f0f0; font:16px 'Segoe UI';")
        self .me_label .setAlignment (Qt .AlignmentFlag .AlignLeft )
        inner_l .addWidget (self .me_label )

        inner_l .addStretch ()

        btn =QPushButton ("Log Out")
        btn .setFixedSize (120 ,44 )
        btn .setCursor (Qt .CursorShape .PointingHandCursor )
        btn .setStyleSheet ("background: #e91e63; color: white; border-radius:8px; font-weight:600;")
        btn .clicked .connect (self ._on_logout )
        inner_l .addWidget (btn ,0 ,Qt .AlignmentFlag .AlignLeft )

        lay .addWidget (inner ,1 )

    def paintEvent (self ,event ):
        p =QPainter (self )
        p .setRenderHint (QPainter .RenderHint .Antialiasing )
        if getattr (self ,'bg',None ):
            try :
                scaled =self .bg .scaled (self .size (),Qt .AspectRatioMode .KeepAspectRatioByExpanding ,Qt .TransformationMode .SmoothTransformation )
                x =(self .width ()-scaled .width ())//2 
                y =(self .height ()-scaled .height ())//2 
                p .drawPixmap (x ,y ,scaled )
            except Exception :
                p .fillRect (self .rect (),QColor (0 ,0 ,0 ))
        else :
            p .fillRect (self .rect (),QColor (0 ,0 ,0 ))
        super ().paintEvent (event )

    def set_gamertag (self ,gamertag :str ):
        try :
            self .me_label .setText (f'You are currently logged in as “{gamertag}”.')
        except Exception :
            pass 

    def _on_logout (self ):

        try :
            main_win =self .parent ()if self .parent ()is not None else self .window ()
            if main_win is not None :
                try :

                    setattr (main_win ,'_username','')
                except Exception :
                    pass 
                try :
                    if hasattr (main_win ,'save_config'):
                        main_win .save_config ()
                except Exception :
                    pass 
                try :

                    try :
                        self .hide ()
                    except Exception :
                        pass 
                    if hasattr (main_win ,'switch_to_main'):
                        main_win .switch_to_main ()
                    if hasattr (main_win ,'open_login'):
                        QTimer .singleShot (120 ,lambda :main_win .open_login ())
                except Exception :
                    pass 
        except Exception :
            pass 




def main ():
    try :

        app =QApplication (sys .argv )
        try :
            from PyQt6 .QtGui import QFont ,QFontDatabase 

            avail =QFontDatabase ().families ()
            if 'Avenir'in avail :
                app .setFont (QFont ('Avenir',12 ))
            else :

                app .setFont (QFont ('Segoe UI',12 ))
        except Exception :
            pass 
        # Iniciar comprobación de actualizaciones en background (si está configurado)
        try:
            try:
                config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), CONFIG_FILE)
                manifest_url = None
                if os.path.exists(config_path):
                    try:
                        with open(config_path, 'r', encoding='utf-8') as f:
                            cfg = json.load(f) or {}
                        manifest_url = cfg.get('update_manifest_url')
                    except Exception:
                        manifest_url = None
            except Exception:
                manifest_url = None
            # Lanza la comprobación en segundo plano
            check_for_updates_async(manifest_url)
        except Exception:
            pass

        w =LauncherWindow ()
        w .show ()
        # Centrar la ventana en pantalla una vez mostrada (delay pequeño para asegurar geometría)
        try:
            QTimer.singleShot(10, lambda: center_widget(w))
        except Exception:
            try:
                # fallback directo
                center_widget(w)
            except Exception:
                pass
        sys .exit (app .exec ())
    except Exception as e :

        tb =traceback .format_exc ()
        print ("[Allio] Error al iniciar la aplicación:\n",tb )
        try :

            if 'QApplication'in globals ():
                app =QApplication .instance ()or QApplication (sys .argv )
                QMessageBox .critical (None ,APP_TITLE ,"Error al iniciar la aplicación:\n\n"+str (e )+"\n\nRevisa la consola para más detalles.")
        except Exception :
            pass 

        sys .exit (1 )

if __name__ =="__main__":
    main ()
    
    
    
    
    
    
    
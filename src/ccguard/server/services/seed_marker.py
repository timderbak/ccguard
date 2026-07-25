"""Маркер версии справочников — пропуск повторного сидирования.

Каждый старт сервера прогонял весь блок сид-загрузчиков (индикаторы, техники,
кросс-ссылки, детекторы, сценарии). Все они идемпотентны, но идемпотентность
не бесплатна: чтобы понять «уже загружено», каждый делает SELECT на строку —
это ~180 мс на пустой работе при каждом рестарте.

Здесь дешёвая проверка «а изменилось ли вообще что-нибудь»: хеш содержимого
YAML-файлов справочников. Совпал с записанным в прошлый раз — значит данные те
же, сиды заведомо будут no-op, блок можно пропустить целиком. Не совпал (файл
поправили, вышло обновление, откатились на старую версию) — сиды отрабатывают
как обычно и маркер переписывается.

Почему хеш содержимого, а не номер версии вручную: номер надо не забыть
поднять, а хеш нельзя забыть — он считается от того, что реально лежит на
диске. Файл пропал или не читается — считаем, что состав изменился, и сиды
выполняются (безопасный отказ в сторону «сделать работу», а не «пропустить»).
"""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from sqlmodel import Session

from ccguard.server.services.settings_service import get_setting, set_setting

log = logging.getLogger(__name__)

MARKER_KEY = "seed.reference_digest"

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
# Только справочники, которые грузит стартовый блок. default_policy.yaml сюда
# НЕ входит — он не сид, а бутстрап политики с отдельным жизненным циклом.
_SEED_FILES: tuple[str, ...] = (
    "threat_indicators_seed.yaml",
    "techniques_seed.yaml",
    "technique_crosswalk_seed.yaml",
    "detector_mappings_seed.yaml",
    "chain_scenarios_seed.yaml",
)


def reference_digest(data_dir: Path | None = None) -> str:
    """sha256 по содержимому всех сид-файлов (имя + байты, в стабильном порядке).

    Имя файла подмешивается, чтобы переименование тоже меняло отпечаток.
    Нечитаемый/отсутствующий файл даёт маркер ``missing``: отпечаток изменится
    и сиды отработают — лучше лишний раз выполнить, чем пропустить нужное.
    """
    d = data_dir or _DATA_DIR
    h = hashlib.sha256()
    for name in sorted(_SEED_FILES):
        h.update(name.encode("utf-8"))
        try:
            h.update((d / name).read_bytes())
        except OSError:
            h.update(b"missing")
    return h.hexdigest()[:32]


def is_current(session: Session, *, digest: str | None = None) -> bool:
    """True, если справочники в БД уже соответствуют файлам на диске."""
    want = digest or reference_digest()
    return get_setting(session, MARKER_KEY) == want


def mark_current(session: Session, *, digest: str | None = None) -> None:
    """Записать отпечаток загруженных справочников."""
    set_setting(session, MARKER_KEY, digest or reference_digest())

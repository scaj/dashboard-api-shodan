"""shodan_common.py
Funciones compartidas: load_api_key, save_json, setup_logger
"""
from __future__ import annotations
import os
import json
import logging
from logging.handlers import RotatingFileHandler
from typing import Any


def load_api_key() -> str:
    api_key = os.getenv('SHODAN_API_KEY')
    if not api_key:
        raise RuntimeError('La variable de entorno SHODAN_API_KEY no está definida')
    return api_key


def save_json(path: str, data: Any) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def setup_logger(name: str = 'shodan_pro', log_file: str | None = None, level: str = 'INFO') -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        # Ya configurado
        return logger
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s - %(message)s')

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    if log_file:
        fh = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding='utf-8')
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger

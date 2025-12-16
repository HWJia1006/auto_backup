# -*- coding: utf-8 -*-
"""
轻量离线备份脚本（GUI）

功能概述：
- 选择监控源文件夹
- 选择两个备份目标（OneDrive文件夹与本地硬盘任意目录）
- 配置备份频率（定期扫描间隔，单位秒）与文件类型过滤（包含型）
- 实时监控（watchdog）创建/修改/删除/移动事件
- 顺序思维处理队列（单工作线程，保证事件顺序一致性）
- 版本历史（SQLite）与冲突解决（保留下行副本）
- 保持原始目录结构复制
- 大文件复制进度显示
- 过滤常见库目录（不备份python/JS等库）
- 完整日志记录到 backup.log

安装依赖：
pip install PySide6 watchdog
（首次运行自动创建 SQLite 数据库与配置文件）
"""

import os
import sys
import json
import time
import uuid
import queue
import shutil
import hashlib
import logging
import threading
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Tuple

from PySide6 import QtCore, QtWidgets
from PySide6.QtCore import Signal, Slot, Qt
import ctypes

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent


# 路径常量
APP_DIR = Path(__file__).resolve().parent
LOG_PATH = APP_DIR / "backup.log"
CONFIG_PATH = APP_DIR / "backup_config.json"
JSON_LOG_DIR = APP_DIR / "logs"


# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("backup")


# 默认过滤（不备份库、构建、缓存等）
DEFAULT_EXCLUDE_DIR_NAMES = [
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "venv",
    ".venv",
    "env",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "out",
    "target",
    "Pods",
    ".gradle",
    ".idea",
    ".vscode",
    "site-packages",
    "Lib",  # Python安装目录的Lib
    "Scripts",  # Python安装目录的Scripts
    ".cache",
    ".next",
    ".turbo",
    ".yarn",
    ".pnpm-store",
    ".parcel-cache",
]

DEFAULT_EXCLUDE_FILE_SUFFIXES = [
    ".pyc",
    ".pyo",
    ".pyd",
    ".dll",
    ".so",
    ".tmp",
    ".temp",
    ".log",
    ".lock",
    ".class",
    ".obj",
    ".o",
    ".a",
    ".lib",
]

COMMON_TYPES = [
    "txt",
    "md",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "pdf",
    "py",
    "ipynb",
    "js",
    "ts",
    "json",
    "xml",
    "html",
    "css",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "bmp",
    "svg",
    "c",
    "cpp",
    "h",
    "hpp",
    "java",
    "go",
    "rs",
    "rb",
    "cs",
    "sh",
    "ps1",
    "bat",
]


@dataclass
class AppConfig:
    source_dir: str = ""
    onedrive_target: str = ""
    local_target: str = ""
    scan_interval_sec: int = 0  # 0 表示仅实时监控，不做周期扫描
    include_types: List[str] = None
    exclude_dir_names: List[str] = None
    exclude_file_suffixes: List[str] = None
    backup_on_save: bool = True
    target_subdir: str = "backup"

    def __post_init__(self):
        if self.include_types is None:
            self.include_types = []
        if self.exclude_dir_names is None:
            self.exclude_dir_names = DEFAULT_EXCLUDE_DIR_NAMES.copy()
        if self.exclude_file_suffixes is None:
            self.exclude_file_suffixes = DEFAULT_EXCLUDE_FILE_SUFFIXES.copy()

    @staticmethod
    def load(path: Path) -> "AppConfig":
        if path.exists():
            try:
                data = json.load(open(path, "r", encoding="utf-8"))
                return AppConfig(**data)
            except Exception as e:
                logger.error(f"加载配置失败：{e}")
        return AppConfig()

    def save(self, path: Path):
        try:
            json.dump(
                asdict(self),
                open(path, "w", encoding="utf-8"),
                ensure_ascii=False,
                indent=2,
            )
        except Exception as e:
            logger.error(f"保存配置失败：{e}")


class JSONLogger:
    def __init__(self, log_dir: Path, retention_days: int = 7):
        self.log_dir = log_dir
        self.retention_days = retention_days
        self._lock = threading.Lock()
        self._last_cleanup = 0.0
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def _file_for_today(self) -> Path:
        day = datetime.now().strftime("%Y-%m-%d")
        return self.log_dir / f"backup-{day}.jsonl"

    def _write_json_line(self, path: Path, obj: Dict):
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        except Exception as e:
            try:
                fb = self.log_dir / "fallback-errors.jsonl"
                with open(fb, "a", encoding="utf-8") as ff:
                    ff.write(
                        json.dumps(
                            {
                                "ts": datetime.now().isoformat(),
                                "type": "log_write_failed",
                                "target": str(path),
                                "error": str(e),
                                "entry": obj,
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )
            except Exception as e2:
                logger.error(f"日志写入失败且回退失败：{e2}")

    def log_change(self, entry: Dict):
        with self._lock:
            self._write_json_line(self._file_for_today(), entry)
            now = time.time()
            if now - self._last_cleanup > 3600:
                self._cleanup_old()
                self._last_cleanup = now

    def log_error(self, path: str, message: str):
        entry = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "type": "error",
            "path": path,
            "message": message,
        }
        self.log_change(entry)

    def _cleanup_old(self):
        try:
            cutoff = datetime.now().timestamp() - self.retention_days * 86400
            for p in self.log_dir.glob("backup-*.jsonl"):
                try:
                    stat = p.stat()
                    if stat.st_mtime < cutoff:
                        p.unlink(missing_ok=True)
                except Exception:
                    continue
        except Exception as e:
            logger.error(f"日志清理失败：{e}")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_free_space(target_dir: Path, size_needed: int) -> bool:
    try:
        root = Path(target_dir.anchor or str(target_dir))
        usage = shutil.disk_usage(root)
        return usage.free >= max(size_needed, 1)
    except Exception as e:
        logger.error(f"检查空间失败：{e}")
        return False


class EventItem:
    def __init__(self, action: str, src_path: str, dest_path: Optional[str] = None):
        self.action = action  # "created"|"modified"|"deleted"|"moved"
        self.src_path = src_path
        self.dest_path = dest_path
        self.ts = time.time()


class FSHandler(FileSystemEventHandler):
    def __init__(self, enqueue_func, src_root: Path, cfg: AppConfig):
        super().__init__()
        self.enqueue = enqueue_func
        self.src_root = src_root
        self.cfg = cfg

    def _should_ignore(self, path: Path) -> bool:
        parts = {p for p in path.parts}
        if any(name in parts for name in self.cfg.exclude_dir_names):
            return True
        if path.name.startswith("~$"):
            return True
        suffix = path.suffix.lower()
        if suffix in self.cfg.exclude_file_suffixes:
            return True
        if self.cfg.include_types:
            ext = suffix.lstrip(".")
            if ext and ext not in {t.lower() for t in self.cfg.include_types}:
                return True
        return False

    def on_created(self, event: FileSystemEvent):
        if event.is_directory:
            return
        p = Path(event.src_path)
        if self._should_ignore(p):
            return
        if not getattr(self.cfg, "backup_on_save", True):
            return
        self.enqueue(EventItem("created", event.src_path))

    def on_modified(self, event: FileSystemEvent):
        if event.is_directory:
            return
        p = Path(event.src_path)
        if self._should_ignore(p):
            return
        if not getattr(self.cfg, "backup_on_save", True):
            return
        self.enqueue(EventItem("modified", event.src_path))

    def on_deleted(self, event: FileSystemEvent):
        if event.is_directory:
            return
        p = Path(event.src_path)
        if self._should_ignore(p):
            return
        self.enqueue(EventItem("deleted", event.src_path))

    def on_moved(self, event: FileSystemEvent):
        if event.is_directory:
            return
        src = Path(event.src_path)
        dst = Path(event.dest_path)
        if self._should_ignore(src) or self._should_ignore(dst):
            return
        self.enqueue(EventItem("moved", event.src_path, event.dest_path))


class BackupWorker(QtCore.QThread):
    progress_signal = Signal(str, int, int)  # path, copied_bytes, total_bytes
    completed_signal = Signal(dict)  # change entry
    error_signal = Signal(str, str)  # path, message
    note_signal = Signal(str)  # free-form status message

    def __init__(
        self,
        cfg: AppConfig,
        json_logger: JSONLogger,
        src_root: Path,
        event_queue: queue.Queue,
    ):
        super().__init__()
        self.cfg = cfg
        self.logger = json_logger
        self.src_root = src_root
        self.event_queue = event_queue
        self._stopping = False

    def stop(self):
        self._stopping = True

    def _rel(self, path: Path) -> Path:
        try:
            return path.relative_to(self.src_root)
        except Exception:
            return Path(path.name)

    def _target_paths(self, src_path: Path) -> List[Tuple[str, Path]]:
        rel = self._rel(src_path)
        result = []
        if self.cfg.onedrive_target:
            result.append(
                (
                    "onedrive",
                    Path(self.cfg.onedrive_target)
                    / (self.cfg.target_subdir or "backup")
                    / rel,
                )
            )
        if self.cfg.local_target:
            result.append(
                (
                    "local",
                    Path(self.cfg.local_target)
                    / (self.cfg.target_subdir or "backup")
                    / rel,
                )
            )
        return result

    def _copy_with_progress(self, src: Path, dst: Path) -> Tuple[int, str]:
        dst.parent.mkdir(parents=True, exist_ok=True)
        total = src.stat().st_size if src.exists() else 0
        copied = 0
        h = hashlib.sha256()
        with open(src, "rb") as fsrc, open(dst, "wb") as fdst:
            while True:
                chunk = fsrc.read(8 * 1024 * 1024)
                if not chunk:
                    break
                fdst.write(chunk)
                h.update(chunk)
                copied += len(chunk)
                self.progress_signal.emit(str(src), copied, total)
        return total, h.hexdigest()

    def _handle_conflict(self, dst: Path, new_hash: str) -> Path:
        try:
            if dst.exists():
                old_hash = sha256_file(dst)
                if old_hash != new_hash:
                    suffix = datetime.now().strftime("%Y%m%d-%H%M%S")
                    conflict_dst = dst.with_suffix(dst.suffix + f".conflict-{suffix}")
                    return conflict_dst
        except Exception:
            pass
        return dst

    def run(self):
        while not self._stopping:
            try:
                item: EventItem = self.event_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            src_path = Path(item.src_path)
            try:
                if item.action in ("created", "modified", "moved"):
                    source = (
                        Path(item.dest_path) if item.action == "moved" else src_path
                    )
                    if not source.exists():
                        self.note_signal.emit(f"源文件不存在，略过：{source}")
                        continue

                    targets = self._target_paths(source)
                    size = source.stat().st_size
                    if any(t for _, t in targets):
                        for tag, dst in targets:
                            if not ensure_free_space(dst.parent, size):
                                msg = f"{tag}空间不足：需要 {size} 字节"
                                self.error_signal.emit(str(source), msg)
                                change_entry = {
                                    "id": str(uuid.uuid4()),
                                    "path": str(source),
                                    "action": item.action,
                                    "timestamp": datetime.now().isoformat(),
                                    "size": size,
                                    "hash": None,
                                    "onedrive_target": (
                                        str(dst) if tag == "onedrive" else None
                                    ),
                                    "local_target": (
                                        str(dst) if tag == "local" else None
                                    ),
                                    "status": "failed",
                                    "error": msg,
                                }
                                self.logger.log_change(change_entry)
                                self.completed_signal.emit(change_entry)
                                continue

                            try:
                                total_bytes, file_hash = self._copy_with_progress(
                                    source, dst
                                )
                                dst_final = self._handle_conflict(dst, file_hash)
                                if dst_final != dst:
                                    shutil.move(dst, dst_final)
                                change_entry = {
                                    "id": str(uuid.uuid4()),
                                    "path": str(source),
                                    "action": item.action,
                                    "timestamp": datetime.now().isoformat(),
                                    "size": total_bytes,
                                    "hash": file_hash,
                                    "onedrive_target": (
                                        str(dst_final) if tag == "onedrive" else None
                                    ),
                                    "local_target": (
                                        str(dst_final) if tag == "local" else None
                                    ),
                                    "status": "ok",
                                    "error": None,
                                }
                                self.logger.log_change(change_entry)
                                self.completed_signal.emit(change_entry)
                            except PermissionError as e:
                                msg = f"权限错误：{e}"
                                self.error_signal.emit(str(source), msg)
                                change_entry = {
                                    "id": str(uuid.uuid4()),
                                    "path": str(source),
                                    "action": item.action,
                                    "timestamp": datetime.now().isoformat(),
                                    "size": size,
                                    "hash": None,
                                    "onedrive_target": None,
                                    "local_target": None,
                                    "status": "failed",
                                    "error": msg,
                                }
                                self.logger.log_change(change_entry)
                                self.completed_signal.emit(change_entry)
                            except Exception as e:
                                msg = f"复制失败：{e}"
                                self.error_signal.emit(str(source), msg)
                                change_entry = {
                                    "id": str(uuid.uuid4()),
                                    "path": str(source),
                                    "action": item.action,
                                    "timestamp": datetime.now().isoformat(),
                                    "size": size,
                                    "hash": None,
                                    "onedrive_target": None,
                                    "local_target": None,
                                    "status": "failed",
                                    "error": msg,
                                }
                                self.logger.log_change(change_entry)
                                self.completed_signal.emit(change_entry)

                elif item.action == "deleted":
                    change_entry = {
                        "id": str(uuid.uuid4()),
                        "path": str(src_path),
                        "action": item.action,
                        "timestamp": datetime.now().isoformat(),
                        "size": None,
                        "hash": None,
                        "onedrive_target": None,
                        "local_target": None,
                        "status": "ok",
                        "error": None,
                    }
                    self.logger.log_change(change_entry)
                    self.completed_signal.emit(change_entry)

            except Exception as e:
                self.error_signal.emit(str(src_path), f"处理事件失败：{e}")


class RecentScanner:
    """
    最近文件扫描（按 mtime 排序）
    """

    def __init__(self, cfg: AppConfig):
        self.cfg = cfg

    def recent_files(self, root: Path, limit: int = 50) -> List[Path]:
        items: List[Tuple[float, Path]] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in self.cfg.exclude_dir_names]
            for fn in filenames:
                p = Path(dirpath) / fn
                if p.suffix.lower() in self.cfg.exclude_file_suffixes:
                    continue
                if self.cfg.include_types:
                    ext = p.suffix.lower().lstrip(".")
                    if ext and ext not in {t.lower() for t in self.cfg.include_types}:
                        continue
                try:
                    mtime = p.stat().st_mtime
                    items.append((mtime, p))
                except Exception:
                    continue
        items.sort(key=lambda x: x[0], reverse=True)
        return [p for _, p in items[:limit]]


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("离线备份（OneDrive/本地）")
        self.resize(980, 680)

        self.cfg = AppConfig.load(CONFIG_PATH)
        self.json_logger = JSONLogger(JSON_LOG_DIR, retention_days=7)
        self.event_queue: queue.Queue = queue.Queue()
        self.observer: Optional[Observer] = None
        self.worker: Optional[BackupWorker] = None
        self.scanner = RecentScanner(self.cfg)
        self.scan_timer: Optional[QtCore.QTimer] = None

        self._init_ui()
        self._apply_cfg_to_ui()

    def closeEvent(self, event):
        try:
            self._stop_monitoring()
        except Exception:
            pass
        super().closeEvent(event)

    def _init_ui(self):
        cw = QtWidgets.QWidget()
        self.setCentralWidget(cw)
        root_layout = QtWidgets.QVBoxLayout(cw)

        # 源与目标选择
        src_group = QtWidgets.QGroupBox("源文件夹与目标选择")
        src_layout = QtWidgets.QGridLayout(src_group)

        self.src_edit = QtWidgets.QLineEdit()
        self.src_btn = QtWidgets.QPushButton("选择源文件夹")
        self.src_btn.clicked.connect(self._choose_src)

        self.onedrive_edit = QtWidgets.QLineEdit()
        self.onedrive_btn = QtWidgets.QPushButton("选择OneDrive文件夹")
        self.onedrive_btn.clicked.connect(self._choose_onedrive)

        self.local_edit = QtWidgets.QLineEdit()
        self.local_btn = QtWidgets.QPushButton("选择本地备份文件夹")
        self.local_btn.clicked.connect(self._choose_local)
        self.local_drive_btn = QtWidgets.QPushButton("选择本地驱动器")
        self.local_drive_btn.clicked.connect(self._choose_local_drive)

        src_layout.addWidget(QtWidgets.QLabel("源文件夹"), 0, 0)
        src_layout.addWidget(self.src_edit, 0, 1)
        src_layout.addWidget(self.src_btn, 0, 2)

        src_layout.addWidget(QtWidgets.QLabel("OneDrive文件夹"), 1, 0)
        src_layout.addWidget(self.onedrive_edit, 1, 1)
        src_layout.addWidget(self.onedrive_btn, 1, 2)

        src_layout.addWidget(QtWidgets.QLabel("本地备份文件夹"), 2, 0)
        src_layout.addWidget(self.local_edit, 2, 1)
        src_layout.addWidget(self.local_btn, 2, 2)
        src_layout.addWidget(self.local_drive_btn, 2, 3)

        root_layout.addWidget(src_group)

        # 配置面板
        cfg_group = QtWidgets.QGroupBox("备份配置")
        cfg_layout = QtWidgets.QGridLayout(cfg_group)

        self.scan_spin = QtWidgets.QSpinBox()
        self.scan_spin.setRange(0, 86400)
        self.scan_spin.setValue(0)
        self.scan_spin.setSuffix(" 秒")
        self.scan_spin.setToolTip("周期扫描间隔（0 表示仅实时监控）")

        self.on_save_check = QtWidgets.QCheckBox("保存即备份（实时）")

        self.type_checks: List[QtWidgets.QCheckBox] = []
        self.types_widget = QtWidgets.QWidget()
        self.types_layout = QtWidgets.QGridLayout(self.types_widget)
        for i, ext in enumerate(COMMON_TYPES):
            cb = QtWidgets.QCheckBox(ext)
            self.type_checks.append(cb)
            r, c = divmod(i, 6)
            self.types_layout.addWidget(cb, r, c)
        self.types_scroll = QtWidgets.QScrollArea()
        self.types_scroll.setWidget(self.types_widget)
        self.types_scroll.setWidgetResizable(True)

        self.target_subdir_edit = QtWidgets.QLineEdit()
        self.scan_types_btn = QtWidgets.QPushButton("扫描并添加类型")
        self.scan_types_btn.clicked.connect(self._scan_and_add_types)

        self.save_cfg_btn = QtWidgets.QPushButton("保存配置")
        self.save_cfg_btn.clicked.connect(self._save_cfg)

        cfg_layout.addWidget(QtWidgets.QLabel("备份频率（周期扫描）"), 0, 0)
        cfg_layout.addWidget(self.scan_spin, 0, 1)
        cfg_layout.addWidget(self.on_save_check, 1, 0, 1, 2)
        cfg_layout.addWidget(QtWidgets.QLabel("文件类型（包含型）"), 2, 0)
        cfg_layout.addWidget(self.types_scroll, 2, 1)
        cfg_layout.addWidget(QtWidgets.QLabel("目标子文件夹名"), 3, 0)
        cfg_layout.addWidget(self.target_subdir_edit, 3, 1)
        cfg_layout.addWidget(self.scan_types_btn, 4, 0, 1, 2)
        cfg_layout.addWidget(self.save_cfg_btn, 5, 0, 1, 2)

        root_layout.addWidget(cfg_group)

        # 控制按钮
        btn_layout = QtWidgets.QHBoxLayout()
        self.start_btn = QtWidgets.QPushButton("开始监控")
        self.stop_btn = QtWidgets.QPushButton("停止监控")
        self.rescan_btn = QtWidgets.QPushButton("手动检索最近修改")
        self.start_btn.clicked.connect(self._start_monitoring)
        self.stop_btn.clicked.connect(self._stop_monitoring)
        self.rescan_btn.clicked.connect(self._manual_recent_scan)
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.rescan_btn)
        root_layout.addLayout(btn_layout)

        # 状态显示区域
        status_group = QtWidgets.QGroupBox("最近备份操作记录")
        status_layout = QtWidgets.QVBoxLayout(status_group)

        self.table = QtWidgets.QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["时间", "动作", "路径", "大小", "状态", "OneDrive目标", "本地目标"]
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(
            QtWidgets.QHeaderView.Stretch
        )
        status_layout.addWidget(self.table)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setMinimum(0)
        self.progress.setMaximum(100)
        self.progress.setValue(0)
        status_layout.addWidget(self.progress)

        self.status_label = QtWidgets.QLabel("就绪")
        status_layout.addWidget(self.status_label)

        root_layout.addWidget(status_group)

    def _apply_cfg_to_ui(self):
        self.src_edit.setText(self.cfg.source_dir)
        self.onedrive_edit.setText(self.cfg.onedrive_target)
        self.local_edit.setText(self.cfg.local_target)
        self.scan_spin.setValue(int(self.cfg.scan_interval_sec or 0))
        selected = {t.lower() for t in (self.cfg.include_types or [])}
        for cb in self.type_checks:
            cb.setChecked(cb.text().lower() in selected)
        self.on_save_check.setChecked(bool(getattr(self.cfg, "backup_on_save", True)))
        self.target_subdir_edit.setText(self.cfg.target_subdir or "backup")

    def _save_cfg(self):
        self.cfg.source_dir = self.src_edit.text().strip()
        self.cfg.onedrive_target = self.onedrive_edit.text().strip()
        self.cfg.local_target = self.local_edit.text().strip()
        self.cfg.scan_interval_sec = int(self.scan_spin.value())
        self.cfg.include_types = [
            cb.text().lower() for cb in self.type_checks if cb.isChecked()
        ]
        self.cfg.backup_on_save = self.on_save_check.isChecked()
        self.cfg.target_subdir = self.target_subdir_edit.text().strip() or "backup"
        self.cfg.save(CONFIG_PATH)
        self.status_label.setText("配置已保存")
        logger.info("配置已保存")

    def _choose_src(self):
        d = QtWidgets.QFileDialog.getExistingDirectory(
            self, "选择源文件夹", self.cfg.source_dir or str(Path.home())
        )
        if d:
            self.src_edit.setText(d)

    def _choose_onedrive(self):
        d = QtWidgets.QFileDialog.getExistingDirectory(
            self, "选择OneDrive文件夹", self.cfg.onedrive_target or str(Path.home())
        )
        if d:
            self.onedrive_edit.setText(d)

    def _choose_local(self):
        d = QtWidgets.QFileDialog.getExistingDirectory(
            self, "选择本地备份文件夹", self.cfg.local_target or str(Path.home())
        )
        if d:
            self.local_edit.setText(d)

    def _choose_local_drive(self):
        try:
            buf = ctypes.create_unicode_buffer(256)
            ctypes.windll.kernel32.GetLogicalDriveStringsW(256, buf)
            drives = [d for d in buf.value.split("\x00") if d]
            if not drives:
                QtWidgets.QMessageBox.warning(self, "提示", "未检测到本地驱动器")
                return
            item, ok = QtWidgets.QInputDialog.getItem(
                self, "选择驱动器", "驱动器：", drives, 0, False
            )
            if ok and item:
                self.local_edit.setText(item)
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "错误", f"驱动器枚举失败：{e}")

    def _start_monitoring(self):
        self._save_cfg()
        if not self.cfg.source_dir:
            QtWidgets.QMessageBox.warning(self, "提示", "请先选择源文件夹")
            return
        src_root = Path(self.cfg.source_dir)
        if not src_root.exists():
            QtWidgets.QMessageBox.warning(self, "提示", "源文件夹不存在")
            return

        if self.observer is not None:
            QtWidgets.QMessageBox.information(self, "提示", "监控已启动")
            return

        self._check_and_prepare_targets()
        queued_count = self._initial_backup_or_sync(src_root)

        self.observer = Observer()
        handler = FSHandler(self.event_queue.put, src_root, self.cfg)
        self.observer.schedule(handler, str(src_root), recursive=True)
        self.observer.start()

        self.worker = BackupWorker(
            self.cfg, self.json_logger, src_root, self.event_queue
        )
        self.worker.progress_signal.connect(self._on_progress)
        self.worker.completed_signal.connect(self._on_completed)
        self.worker.error_signal.connect(self._on_error)
        self.worker.note_signal.connect(self._on_note)
        self.worker.start()

        self._setup_scan_timer()

        self.status_label.setText(f"监控已启动（初始队列 {queued_count}）")
        logger.info("监控已启动")

    def _scan_and_add_types(self):
        try:
            src_root = Path(self.src_edit.text().strip() or self.cfg.source_dir)
            if not src_root or not src_root.exists():
                QtWidgets.QMessageBox.warning(self, "提示", "请先选择有效的源文件夹")
                return
            found: set = set()
            for dirpath, dirnames, filenames in os.walk(src_root):
                dirnames[:] = [
                    d for d in dirnames if d not in (self.cfg.exclude_dir_names or [])
                ]
                for fn in filenames:
                    p = Path(dirpath) / fn
                    suf = p.suffix.lower()
                    if not suf:
                        continue
                    if suf in (self.cfg.exclude_file_suffixes or []):
                        continue
                    ext = suf.lstrip(".")
                    if ext:
                        found.add(ext)
            current = {t.lower() for t in (self.cfg.include_types or [])}
            new_types = sorted(found - current)
            if not new_types:
                QtWidgets.QMessageBox.information(self, "提示", "未发现新的文件类型")
                return
            for ext in new_types:
                cb = QtWidgets.QCheckBox(ext)
                cb.setChecked(True)
                self.type_checks.append(cb)
                i = len(self.type_checks) - 1
                r, c = divmod(i, 6)
                self.types_layout.addWidget(cb, r, c)
            self.cfg.include_types = [
                cb.text().lower() for cb in self.type_checks if cb.isChecked()
            ]
            self.cfg.save(CONFIG_PATH)
            self.status_label.setText(f"已添加新类型：{', '.join(new_types)}")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "错误", f"扫描失败：{e}")
            logger.error(f"扫描类型失败：{e}")

    def _stop_monitoring(self):
        if self.scan_timer:
            self.scan_timer.stop()
            self.scan_timer = None
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=2.0)
            except Exception:
                pass
            self.observer = None
        if self.worker:
            try:
                self.worker.stop()
                self.worker.wait(2000)
            except Exception:
                pass
            self.worker = None
        self.status_label.setText("监控已停止")
        logger.info("监控已停止")

    def _setup_scan_timer(self):
        interval = int(self.cfg.scan_interval_sec or 0)
        if interval > 0:
            self.scan_timer = QtCore.QTimer(self)
            self.scan_timer.timeout.connect(self._periodic_scan_tick)
            self.scan_timer.start(interval * 1000)
            logger.info(f"周期扫描已启用：每 {interval} 秒")

    def _periodic_scan_tick(self):
        try:
            self._do_recent_scan(limit=30)
        except Exception as e:
            logger.error(f"周期扫描失败：{e}")

    def _manual_recent_scan(self):
        try:
            self._do_recent_scan(limit=50)
            QtWidgets.QMessageBox.information(self, "提示", "最近修改检索已加入队列")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "错误", f"检索失败：{e}")

    def _do_recent_scan(self, limit: int = 50):
        src_root = Path(self.cfg.source_dir)
        files = self.scanner.recent_files(src_root, limit=limit)
        for p in files:
            self.event_queue.put(EventItem("modified", str(p)))
        self.status_label.setText(f"加入最近文件 {len(files)} 个到队列")

    def _should_ignore_path(self, p: Path) -> bool:
        parts = {x for x in p.parts}
        if any(name in parts for name in (self.cfg.exclude_dir_names or [])):
            return True
        if p.name.startswith("~$"):
            return True
        suf = p.suffix.lower()
        if suf in (self.cfg.exclude_file_suffixes or []):
            return True
        if self.cfg.include_types:
            ext = suf.lstrip(".")
            if ext and ext not in {t.lower() for t in self.cfg.include_types}:
                return True
        return False

    def _iter_source_files(self, src_root: Path):
        for dirpath, dirnames, filenames in os.walk(src_root):
            dirnames[:] = [
                d for d in dirnames if d not in (self.cfg.exclude_dir_names or [])
            ]
            for fn in filenames:
                p = Path(dirpath) / fn
                if self._should_ignore_path(p):
                    continue
                yield p

    def _target_rel(self, src_root: Path, p: Path) -> Path:
        try:
            return p.relative_to(src_root)
        except Exception:
            return Path(p.name)

    def _target_paths_for(self, src_root: Path, p: Path) -> List[Path]:
        rel = self._target_rel(src_root, p)
        targets = []
        sub = self.cfg.target_subdir or "backup"
        if self.cfg.onedrive_target:
            targets.append(Path(self.cfg.onedrive_target) / sub / rel)
        if self.cfg.local_target:
            targets.append(Path(self.cfg.local_target) / sub / rel)
        return targets

    def _needs_copy(self, src_root: Path, p: Path) -> bool:
        for dst in self._target_paths_for(src_root, p):
            try:
                if not dst.exists():
                    return True
                s = p.stat()
                d = dst.stat()
                if s.st_size != d.st_size or s.st_mtime > d.st_mtime:
                    return True
            except Exception:
                return True
        return False

    def _initial_backup_or_sync(self, src_root: Path) -> int:
        targets_exist = []
        sub = self.cfg.target_subdir or "backup"
        if self.cfg.onedrive_target:
            targets_exist.append((Path(self.cfg.onedrive_target) / sub).exists())
        if self.cfg.local_target:
            targets_exist.append((Path(self.cfg.local_target) / sub).exists())
        have_all = all(targets_exist) if targets_exist else False

        count = 0
        if have_all:
            for p in self._iter_source_files(src_root):
                if self._needs_copy(src_root, p):
                    self.event_queue.put(EventItem("modified", str(p)))
                    count += 1
        else:
            for p in self._iter_source_files(src_root):
                self.event_queue.put(EventItem("modified", str(p)))
                count += 1
        return count

    def _check_and_prepare_targets(self):
        sub = self.cfg.target_subdir or "backup"
        for tag, base in [
            ("onedrive", self.onedrive_edit.text().strip()),
            ("local", self.local_edit.text().strip()),
        ]:
            if not base:
                continue
            try:
                target_sub = Path(base) / sub
                target_sub.mkdir(parents=True, exist_ok=True)
                test = target_sub / f".writable-test-{uuid.uuid4().hex}.tmp"
                with open(test, "wb") as f:
                    f.write(b"ok")
                test.unlink(missing_ok=True)
            except PermissionError as e:
                msg = f"{tag}写入权限错误：{e}"
                logger.error(msg)
                self.json_logger.log_error(base, msg)
                QtWidgets.QMessageBox.warning(self, "权限错误", msg)
            except Exception as e:
                msg = f"{tag}路径检查失败：{e}"
                logger.error(msg)
                self.json_logger.log_error(base, msg)

    @Slot(str, int, int)
    def _on_progress(self, path: str, copied: int, total: int):
        val = int(copied * 100 / total) if total > 0 else 0
        self.progress.setValue(val)
        self.statusBar().showMessage(f"复制进度 {val}% - {path}")

    @Slot(dict)
    def _on_completed(self, entry: Dict):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(
            row, 0, QtWidgets.QTableWidgetItem(entry.get("timestamp") or "")
        )
        self.table.setItem(
            row, 1, QtWidgets.QTableWidgetItem(entry.get("action") or "")
        )
        self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(entry.get("path") or ""))
        size_val = entry.get("size")
        self.table.setItem(
            row,
            3,
            QtWidgets.QTableWidgetItem(str(size_val) if size_val is not None else ""),
        )
        self.table.setItem(
            row, 4, QtWidgets.QTableWidgetItem(entry.get("status") or "")
        )
        self.table.setItem(
            row, 5, QtWidgets.QTableWidgetItem(entry.get("onedrive_target") or "")
        )
        self.table.setItem(
            row, 6, QtWidgets.QTableWidgetItem(entry.get("local_target") or "")
        )
        self.table.scrollToBottom()
        self.status_label.setText(f"完成：{entry.get('action')} - {entry.get('path')}")
        logger.info(f"完成：{entry.get('action')} - {entry.get('path')}")

    @Slot(str, str)
    def _on_error(self, path: str, message: str):
        self.status_label.setText(f"错误：{message}")
        logger.error(f"错误：{path} - {message}")

    @Slot(str)
    def _on_note(self, message: str):
        self.status_label.setText(message)
        logger.info(message)


def main():
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

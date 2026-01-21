import sys
import os
import json
import shutil
import threading
import traceback
import time
import faulthandler
import ctypes
import argparse
import uuid
import tempfile
from PySide6.QtGui import QIcon





from dataclasses import dataclass, asdict
from pathlib import Path


from PySide6.QtCore import Qt, QSignalBlocker, QObject, Signal, Slot, QThread
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QFileDialog, QMessageBox,
    QHeaderView, QTextEdit, QProgressBar, QLabel
)

CONFIG_FILE = "backup_config.json"
faulthandler.enable(open("fatal.log", "w", encoding="utf-8"))


def _new_job_id() -> str:
    # Σταθερό id ανά job (persist στο config). Hex = short + file-friendly.
    return uuid.uuid4().hex


def _atomic_write_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    """Atomic write: γράφει σε temp στον ίδιο φάκελο και μετά os.replace()."""
    path.parent.mkdir(parents=True, exist_ok=True)

    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding=encoding,
            newline="\n",
            delete=False,
            dir=str(path.parent),
            prefix=path.name + ".",
            suffix=".tmp",
        ) as f:
            tmp_path = Path(f.name)
            f.write(text)
            f.flush()
            os.fsync(f.fileno())

        os.replace(str(tmp_path), str(path))
    finally:
        # Αν κάτι πήγε στραβά πριν το replace, καθάρισε το temp.
        if tmp_path is not None and tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass


def _ddmmyyyy() -> str:
    # Ημερομηνία σε dd-mm-yyyy (όπως ζητήθηκε)
    return time.strftime("%d-%m-%Y")


def _now_stamp() -> str:
    # Χρονική σήμανση για index log
    return time.strftime("%d-%m-%Y %H:%M:%S")


def _ensure_history_dir(dst_folder: Path) -> Path:
    hist = dst_folder / ".backup_history"
    hist.mkdir(parents=True, exist_ok=True)

    # Κάνε τον φάκελο hidden στα Windows (best-effort)
    try:
        FILE_ATTRIBUTE_HIDDEN = 0x2
        ctypes.windll.kernel32.SetFileAttributesW(str(hist), FILE_ATTRIBUTE_HIDDEN)
    except Exception:
        pass

    return hist


def _append_history_record(dst_folder: Path, job_id: str, record: dict) -> None:
    """Append-only index (NDJSON). Κάθε γραμμή = 1 JSON object."""
    hist_dir = _ensure_history_dir(dst_folder)
    idx_path = hist_dir / f"{job_id}.ndjson"

    with open(idx_path, "a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())


def install_crash_handler():
    def excepthook(exc_type, exc, tb):
        text = "".join(traceback.format_exception(exc_type, exc, tb))
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        Path("crash.log").write_text(f"[{stamp}]\n{text}\n", encoding="utf-8")

        try:
            QMessageBox.critical(None, "Crash", f"Κάτι έσπασε.\nΓράφτηκε crash.log.\n\n{exc}")
        except Exception:
            pass

    sys.excepthook = excepthook


def app_dir() -> Path:
    # Δίπλα στο exe όταν γίνει PyInstaller, αλλιώς δίπλα στο app.py
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def ensure_hidden_logs_dir() -> Path:
    logs = app_dir() / "logs"
    logs.mkdir(parents=True, exist_ok=True)

    # Κάνε τον φάκελο hidden στα Windows (κρυφό)
    try:
        FILE_ATTRIBUTE_HIDDEN = 0x2
        ctypes.windll.kernel32.SetFileAttributesW(str(logs), FILE_ATTRIBUTE_HIDDEN)
    except Exception:
        pass

    return logs


# ---------- Data model ----------
@dataclass
class BackupJob:
    job_id: str
    enabled: bool
    source: str
    destination: str
    archive_enabled: bool = False
    archive_next_seq: int = 1


def load_config() -> list[BackupJob]:
    p = app_dir() / CONFIG_FILE
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        jobs: list[BackupJob] = []
        migrated = False

        for item in data.get("jobs", []):
            jid = item.get("job_id")
            if not isinstance(jid, str) or not jid.strip():
                jid = _new_job_id()
                migrated = True

            if "archive_enabled" not in item:
                migrated = True
            archive_enabled = bool(item.get("archive_enabled", False))

            # Fallback counter στο config (ασφάλεια αν λείπει/σβηστεί το index)
            if "archive_next_seq" not in item:
                migrated = True
            try:
                next_seq = int(item.get("archive_next_seq", 1))
            except Exception:
                next_seq = 1
                migrated = True
            if next_seq < 1:
                next_seq = 1
                migrated = True

            jobs.append(
                BackupJob(
                    job_id=str(jid),
                    enabled=bool(item.get("enabled", True)),
                    source=str(item.get("source", "")),
                    destination=str(item.get("destination", "")),
                    archive_enabled=archive_enabled,
                    archive_next_seq=next_seq,
                )
            )

        # Migration: γράψε πίσω job_id/archival defaults ώστε να μείνουν σταθερά.
        if migrated:
            try:
                save_config(jobs)
            except Exception:
                pass

        return jobs
    except Exception:
        return []


def save_config(jobs: list[BackupJob]) -> None:
    payload = {"jobs": [asdict(j) for j in jobs]}
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    _atomic_write_text(app_dir() / CONFIG_FILE, text, encoding="utf-8")


# ---------- Worker <-> UI decision protocol ----------
class Decision:
    CREATE = "CREATE"
    SKIP = "SKIP"
    CANCEL = "CANCEL"

    OVERWRITE = "OVERWRITE"
    OVERWRITE_ALL = "OVERWRITE_ALL"
    SKIP_ALL = "SKIP_ALL"


class BackupWorker(QObject):
    log = Signal(str)
    progress = Signal(int)
    row_status = Signal(int, str)
    summary = Signal(dict)
    finished = Signal()

    request_create_dest = Signal(int, str)
    request_overwrite = Signal(str, str)

    def __init__(self, selected_jobs: list[tuple[int, BackupJob, int | None]]):
        super().__init__()
        self.selected_jobs = selected_jobs
        self._history_lock = threading.Lock()

        self._lock = threading.Lock()
        self._event = threading.Event()
        self._last_decision: str | None = None

        self._overwrite_all = False
        self._skip_all = False

        self._cancelled = False

        # counters
        self._files_total = 0
        self._files_copied = 0
        self._files_overwritten = 0
        self._files_skipped = 0
        self._jobs_done = 0
        self._jobs_skipped = 0
        self._jobs_errors = 0

    # UI thread replies
    def reply(self, decision: str):
        with self._lock:
            self._last_decision = decision
            if decision == Decision.CANCEL:
                self._cancelled = True
        self._event.set()

    @Slot()
    def cancel(self):
        # Cancel από UI: σταμάτα run + ξεμπλόκαρε τυχόν αναμονή prompt
        with self._lock:
            self._cancelled = True
            self._last_decision = Decision.CANCEL
        self._event.set()

    def _ask_ui(self, signal: Signal, *args) -> str:
        self._event.clear()
        with self._lock:
            self._last_decision = None
        signal.emit(*args)
        self._event.wait()
        with self._lock:
            return self._last_decision or Decision.CANCEL

    def _safe_resolve(self, p: str) -> Path:
        return Path(p).expanduser().resolve()

    def _is_path_inside(self, child: Path, parent: Path) -> bool:
        try:
            child.relative_to(parent)
            return True
        except Exception:
            return False

    def _count_files_in_dir(self, src_dir: Path) -> int:
        c = 0
        for _root, _dirs, files in os.walk(src_dir):
            c += len(files)
        return c

    def _copy_file_with_prompt(self, src: Path, dst: Path) -> None:
        """
        Copy με prompts.
        Μετράει copied/overwritten/skipped.
        """
        if self._cancelled:
            return

        dst_exists = dst.exists()

        if dst_exists:
            if self._skip_all:
                self._files_skipped += 1
                return

            if not self._overwrite_all:
                d = self._ask_ui(self.request_overwrite, str(src), str(dst))

                if d == Decision.CANCEL:
                    self._cancelled = True
                    return
                if d == Decision.SKIP:
                    self._files_skipped += 1
                    return
                if d == Decision.SKIP_ALL:
                    self._skip_all = True
                    self._files_skipped += 1
                    return
                if d == Decision.OVERWRITE_ALL:
                    self._overwrite_all = True
                # OVERWRITE falls through

        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

        if dst_exists:
            self._files_overwritten += 1
        else:
            self._files_copied += 1

    @Slot()
    def run(self):
        start_ts = time.time()
        try:
            # Pre-scan for progress
            total_files = 0
            for _row, job, _run_seq in self.selected_jobs:
                src_s = job.source.strip()
                dst_s = job.destination.strip()
                if not src_s or not dst_s:
                    continue
                src = self._safe_resolve(src_s)
                if src.is_file():
                    total_files += 1
                elif src.is_dir():
                    total_files += self._count_files_in_dir(src)

            self._files_total = max(total_files, 0)

            if self._files_total <= 0:
                self.progress.emit(0)
                self.log.emit("Nothing to do.")
                return

            done_files = 0
            self.progress.emit(0)

            for row, job, run_seq in self.selected_jobs:
                if self._cancelled:
                    self.row_status.emit(row, "Cancelled")
                    break

                self._overwrite_all = False
                self._skip_all = False

                src_s = job.source.strip()
                dst_s = job.destination.strip()

                if not src_s or not dst_s:
                    self.row_status.emit(row, "Invalid paths")
                    self.log.emit(f"[Job {row+1}] Missing source/destination.")
                    self._jobs_errors += 1
                    continue

                src = self._safe_resolve(src_s)
                dst_folder = self._safe_resolve(dst_s)

                if not src.exists():
                    self.row_status.emit(row, "Source missing")
                    self.log.emit(f"[Job {row+1}] Source not found: {src}")
                    self._jobs_errors += 1
                    continue

                if dst_folder.exists() and not dst_folder.is_dir():
                    self.row_status.emit(row, "Dest not folder")
                    self.log.emit(f"[Job {row+1}] Destination is not a folder: {dst_folder}")
                    self._jobs_errors += 1
                    continue

                if not dst_folder.exists():
                    d = self._ask_ui(self.request_create_dest, row, str(dst_folder))
                    if d == Decision.CANCEL:
                        self._cancelled = True
                        self.row_status.emit(row, "Cancelled")
                        break
                    if d == Decision.SKIP:
                        self.row_status.emit(row, "Skipped")
                        self.log.emit(f"[Job {row+1}] Skipped (dest missing): {dst_folder}")
                        self._jobs_skipped += 1
                        continue
                    if d == Decision.CREATE:
                        try:
                            dst_folder.mkdir(parents=True, exist_ok=True)
                        except Exception as e:
                            self.row_status.emit(row, "Create failed")
                            self.log.emit(f"[Job {row+1}] Failed to create destination: {e}")
                            self._jobs_errors += 1
                            continue

                archive_mode = bool(job.archive_enabled and run_seq is not None)
                date_tag = _ddmmyyyy()

                # hard safety
                try:
                    if src.is_dir():
                        if src == dst_folder:
                            self.row_status.emit(row, "Blocked (same folder)")
                            self.log.emit(f"[Job {row+1}] Blocked: source folder equals destination folder.")
                            self._jobs_skipped += 1
                            continue
                        if self._is_path_inside(dst_folder, src):
                            self.row_status.emit(row, "Blocked (dest inside source)")
                            self.log.emit(f"[Job {row+1}] Blocked: destination is inside source folder.")
                            self._jobs_skipped += 1
                            continue
                    else:
                        if archive_mode:
                            final_dst_file = dst_folder / f"{run_seq:02d}_{src.stem}_{date_tag}{src.suffix}"
                        else:
                            final_dst_file = dst_folder / src.name
                        try:
                            if final_dst_file.exists() and final_dst_file.resolve() == src:
                                self.row_status.emit(row, "Blocked (same file)")
                                self.log.emit(f"[Job {row+1}] Blocked: source file equals destination file.")
                                self._jobs_skipped += 1
                                continue
                        except Exception:
                            pass
                except Exception:
                    pass

                self.row_status.emit(row, "Running")
                self.log.emit(f"[Job {row+1}] Start: {src}  ->  {dst_folder}")

                try:
                    # per-job counters (για index log)
                    prev_copied = self._files_copied
                    prev_overwritten = self._files_overwritten
                    prev_skipped = self._files_skipped

                    if src.is_file():
                        if archive_mode:
                            target = dst_folder / f"{run_seq:02d}_{src.stem}_{date_tag}{src.suffix}"
                            if target.exists():
                                raise RuntimeError(f"Archive target already exists: {target}")
                        else:
                            target = dst_folder / src.name

                        self._copy_file_with_prompt(src, target)

                        done_files += 1
                        self.progress.emit(int(done_files * 100 / self._files_total))

                        if self._cancelled:
                            self.row_status.emit(row, "Cancelled")
                            break

                        if archive_mode:
                            record = {
                                "ts": _now_stamp(),
                                "job_id": job.job_id,
                                "seq": int(run_seq),
                                "date": date_tag,
                                "kind": "file",
                                "source": str(src),
                                "destination": str(dst_folder),
                                "created": str(target),
                                "status": "ok",
                                "files": {
                                    "copied": self._files_copied - prev_copied,
                                    "overwritten": self._files_overwritten - prev_overwritten,
                                    "skipped": self._files_skipped - prev_skipped,
                                },
                            }
                            try:
                                with self._history_lock:
                                    _append_history_record(dst_folder, job.job_id, record)
                            except Exception as e:
                                self.log.emit(f"[Job {row+1}] WARN: failed to write index: {e}")

                        self.row_status.emit(row, "Done")
                        self._jobs_done += 1

                    elif src.is_dir():
                        if archive_mode:
                            base_target = dst_folder / f"{run_seq:02d}_{src.name}_{date_tag}"
                            if base_target.exists():
                                raise RuntimeError(f"Archive target already exists: {base_target}")
                        else:
                            base_target = dst_folder / src.name

                        for root, _dirs, files in os.walk(src):
                            if self._cancelled:
                                break

                            root_path = Path(root)
                            rel = root_path.relative_to(src)
                            target_dir = base_target / rel
                            target_dir.mkdir(parents=True, exist_ok=True)

                            for fn in files:
                                if self._cancelled:
                                    break
                                sfile = root_path / fn
                                dfile = target_dir / fn

                                self._copy_file_with_prompt(sfile, dfile)
                                done_files += 1
                                self.progress.emit(int(done_files * 100 / self._files_total))

                        if self._cancelled:
                            self.row_status.emit(row, "Cancelled")
                            self.log.emit(f"[Job {row+1}] Cancelled.")
                            break

                        if archive_mode:
                            record = {
                                "ts": _now_stamp(),
                                "job_id": job.job_id,
                                "seq": int(run_seq),
                                "date": date_tag,
                                "kind": "dir",
                                "source": str(src),
                                "destination": str(dst_folder),
                                "created": str(base_target),
                                "status": "ok",
                                "files": {
                                    "copied": self._files_copied - prev_copied,
                                    "overwritten": self._files_overwritten - prev_overwritten,
                                    "skipped": self._files_skipped - prev_skipped,
                                },
                            }
                            try:
                                with self._history_lock:
                                    _append_history_record(dst_folder, job.job_id, record)
                            except Exception as e:
                                self.log.emit(f"[Job {row+1}] WARN: failed to write index: {e}")

                        self.log.emit(f"[Job {row+1}] Copied folder: {base_target}")
                        self.row_status.emit(row, "Done")
                        self._jobs_done += 1

                    else:
                        self.row_status.emit(row, "Unsupported")
                        self.log.emit(f"[Job {row+1}] Unsupported source type.")
                        self._jobs_errors += 1
                        continue

                except Exception as e:
                    self.row_status.emit(row, "Error")
                    self.log.emit(f"[Job {row+1}] ERROR: {e}")
                    self._jobs_errors += 1

            elapsed = time.time() - start_ts
            if self._cancelled:
                self.log.emit("Run cancelled.")
            else:
                self.log.emit("Run finished.")
                self.progress.emit(100)

            self.summary.emit({
                "cancelled": self._cancelled,
                "elapsed_sec": elapsed,
                "jobs_done": self._jobs_done,
                "jobs_skipped": self._jobs_skipped,
                "jobs_errors": self._jobs_errors,
                "files_total": self._files_total,
                "files_copied": self._files_copied,
                "files_overwritten": self._files_overwritten,
                "files_skipped": self._files_skipped,
            })

        finally:
            self.finished.emit()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowIcon(QIcon(str(app_dir() / "app.ico")))

        self.setWindowTitle("BackupApp")
        self.resize(1020, 620)

        # Saved defaults (μόνιμα) -> αυτά θα τρέχουν και στο autorun/shortcut
        self.saved_jobs: list[BackupJob] = load_config()
        # Draft jobs (προσωρινά edits στο tab Ρυθμίσεις μέχρι να πατήσεις Save)
        self.draft_jobs: list[BackupJob] = [
            BackupJob(
                job_id=j.job_id,
                enabled=j.enabled,
                source=j.source,
                destination=j.destination,
                archive_enabled=j.archive_enabled,
                archive_next_seq=j.archive_next_seq,
            )
            for j in self.saved_jobs
        ]
        # Session-only include state (μόνο στο Backup tab, δεν αποθηκεύεται)
        self.include_state: list[bool] = [j.enabled for j in self.saved_jobs]

        self._thread: QThread | None = None
        self._worker: BackupWorker | None = None

        self._logs_dir = ensure_hidden_logs_dir()
        self._log_file = None  # file handle
        self._last_summary: dict | None = None

        tabs = QTabWidget()
        self.setCentralWidget(tabs)

        # --- Tab: Backup ---
        self.backup_tab = QWidget()
        tabs.addTab(self.backup_tab, "Backup")
        backup_layout = QVBoxLayout(self.backup_tab)

        top_row = QHBoxLayout()
        self.run_btn = QPushButton("Run Backup")
        self.run_btn.setEnabled(False)
        self.run_btn.clicked.connect(self.start_backup)
        top_row.addWidget(self.run_btn)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self.request_cancel)
        top_row.addWidget(self.cancel_btn)

        self.total_progress = QProgressBar()
        self.total_progress.setRange(0, 100)
        self.total_progress.setValue(0)
        top_row.addWidget(QLabel("Progress:"))
        top_row.addWidget(self.total_progress, 1)

        backup_layout.addLayout(top_row)

        self.backup_table = QTableWidget(0, 4)
        self.backup_table.setHorizontalHeaderLabels(["Include", "Source", "Destination", "Status"])
        self.backup_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.backup_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.backup_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.backup_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.backup_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.backup_table.itemChanged.connect(self.on_backup_include_changed)
        backup_layout.addWidget(self.backup_table, 2)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        backup_layout.addWidget(QLabel("Log:"))
        backup_layout.addWidget(self.log_box, 1)

        # --- Tab: Ρυθμίσεις ---
        self.settings_tab = QWidget()
        tabs.addTab(self.settings_tab, "Ρυθμίσεις")
        settings_layout = QVBoxLayout(self.settings_tab)

        btn_row = QHBoxLayout()
        self.add_btn = QPushButton("Add Job")
        self.remove_btn = QPushButton("Remove Selected")
        btn_row.addWidget(self.add_btn)
        btn_row.addWidget(self.remove_btn)
        self.save_btn = QPushButton("Save Defaults")
        btn_row.addWidget(self.save_btn)
        self.shortcut_btn = QPushButton("Create Shortcut")
        btn_row.addWidget(self.shortcut_btn)
        btn_row.addStretch(1)
        settings_layout.addLayout(btn_row)

        self.jobs_table = QTableWidget(0, 6)
        self.jobs_table.setHorizontalHeaderLabels(
            ["Enabled (default)", "Source", "Browse", "Destination", "Browse", "Archive/History"]
        )
        self.jobs_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.jobs_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.jobs_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.jobs_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.jobs_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.jobs_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        settings_layout.addWidget(self.jobs_table)

        self.add_btn.clicked.connect(self.add_job)
        self.remove_btn.clicked.connect(self.remove_selected)

        self.shortcut_btn.clicked.connect(self.create_shortcut)

        self.jobs_table.itemChanged.connect(self.on_settings_changed)
        self.save_btn.clicked.connect(self.save_defaults)

        self.refresh_tables()

    def ui_log(self, msg: str):
        self.log_box.append(msg)

    def file_log(self, msg: str):
        if self._log_file:
            try:
                self._log_file.write(msg + "\n")
                self._log_file.flush()
            except Exception:
                pass

    def log(self, msg: str):
        self.ui_log(msg)
        self.file_log(msg)

    def open_run_log(self):
        stamp = time.strftime("%Y%m%d_%H%M%S")
        path = self._logs_dir / f"backup_{stamp}.log"
        try:
            self._log_file = open(path, "w", encoding="utf-8")
            # κρυφό και το αρχείο (best-effort)
            try:
                FILE_ATTRIBUTE_HIDDEN = 0x2
                ctypes.windll.kernel32.SetFileAttributesW(str(path), FILE_ATTRIBUTE_HIDDEN)
            except Exception:
                pass
        except Exception:
            self._log_file = None

    def close_run_log(self):
        try:
            if self._log_file:
                self._log_file.close()
        except Exception:
            pass
        self._log_file = None

    def refresh_tables(self):
        # Settings table from draft_jobs
        blocker = QSignalBlocker(self.jobs_table)
        try:
            self.jobs_table.setRowCount(0)
            for job in self.draft_jobs:
                row = self.jobs_table.rowCount()
                self.jobs_table.insertRow(row)

                enabled_item = QTableWidgetItem()
                enabled_item.setCheckState(Qt.Checked if job.enabled else Qt.Unchecked)
                enabled_item.setFlags((enabled_item.flags() | Qt.ItemIsUserCheckable) & ~Qt.ItemIsEditable)
                self.jobs_table.setItem(row, 0, enabled_item)

                src_item = QTableWidgetItem(job.source)
                self.jobs_table.setItem(row, 1, src_item)

                browse_src = QPushButton("Browse…")
                browse_src.clicked.connect(lambda _=False, r=row: self.browse_source(r))
                self.jobs_table.setCellWidget(row, 2, browse_src)

                dst_item = QTableWidgetItem(job.destination)
                self.jobs_table.setItem(row, 3, dst_item)

                browse_dst = QPushButton("Browse…")
                browse_dst.clicked.connect(lambda _=False, r=row: self.browse_destination(r))
                self.jobs_table.setCellWidget(row, 4, browse_dst)

                archive_item = QTableWidgetItem()
                archive_item.setCheckState(Qt.Checked if job.archive_enabled else Qt.Unchecked)
                archive_item.setFlags((archive_item.flags() | Qt.ItemIsUserCheckable) & ~Qt.ItemIsEditable)
                self.jobs_table.setItem(row, 5, archive_item)
        finally:
            del blocker

        self.refresh_backup_from_model()

    def refresh_backup_from_model(self):
        blocker = QSignalBlocker(self.backup_table)
        try:
            self.backup_table.setRowCount(0)
            for job in self.saved_jobs:
                row = self.backup_table.rowCount()
                self.backup_table.insertRow(row)

                include_item = QTableWidgetItem()
                # session-only include
                state = self.include_state[row] if row < len(self.include_state) else False
                include_item.setCheckState(Qt.Checked if state else Qt.Unchecked)
                include_item.setFlags((include_item.flags() | Qt.ItemIsUserCheckable) & ~Qt.ItemIsEditable)
                self.backup_table.setItem(row, 0, include_item)

                self.backup_table.setItem(row, 1, QTableWidgetItem(job.source))
                self.backup_table.setItem(row, 2, QTableWidgetItem(job.destination))
                self.backup_table.setItem(row, 3, QTableWidgetItem(""))
        finally:
            del blocker

        self.update_run_button_state()

    def update_run_button_state(self):
        can_run = False
        for row in range(self.backup_table.rowCount()):
            inc = self.backup_table.item(row, 0)
            src = self.backup_table.item(row, 1)
            dst = self.backup_table.item(row, 2)
            if inc and inc.checkState() == Qt.Checked and src and dst and src.text().strip() and dst.text().strip():
                can_run = True
                break
        self.run_btn.setEnabled(can_run and self._thread is None)
        self.cancel_btn.setEnabled(self._thread is not None)

    def on_settings_changed(self, _item: QTableWidgetItem):
        # Draft-only: δεν αποθηκεύει, δεν αλλάζει το Backup tab
        self.sync_draft_from_settings()

    def sync_draft_from_settings(self):
        new_jobs: list[BackupJob] = []
        for row in range(self.jobs_table.rowCount()):
            prev = self.draft_jobs[row] if row < len(self.draft_jobs) else None
            enabled_item = self.jobs_table.item(row, 0)
            src_item = self.jobs_table.item(row, 1)
            dst_item = self.jobs_table.item(row, 3)
            archive_item = self.jobs_table.item(row, 5) if self.jobs_table.columnCount() > 5 else None

            enabled = enabled_item.checkState() == Qt.Checked if enabled_item else True
            src = (src_item.text().strip() if src_item else "").strip()
            dst = (dst_item.text().strip() if dst_item else "").strip()

            archive_enabled = (
                archive_item.checkState() == Qt.Checked
                if archive_item is not None
                else (prev.archive_enabled if prev else False)
            )

            new_jobs.append(
                BackupJob(
                    job_id=(prev.job_id if prev else _new_job_id()),
                    enabled=enabled,
                    source=src,
                    destination=dst,
                    archive_enabled=archive_enabled,
                    archive_next_seq=(prev.archive_next_seq if prev else 1),
                )
            )
        self.draft_jobs = new_jobs

    def add_job(self):
        self.draft_jobs.append(
            BackupJob(
                job_id=_new_job_id(),
                enabled=True,
                source="",
                destination="",
                archive_enabled=False,
                archive_next_seq=1,
            )
        )
        self.refresh_tables()

    def remove_selected(self):
        rows = sorted({i.row() for i in self.jobs_table.selectedIndexes()}, reverse=True)
        if not rows:
            return
        for r in rows:
            if 0 <= r < len(self.draft_jobs):
                self.draft_jobs.pop(r)
        self.refresh_tables()

    def browse_source(self, row: int):
        # Επιλογή source ως αρχείο (file) ή ως φάκελο (folder)
        msg = QMessageBox(self)
        msg.setWindowTitle("Select source")
        msg.setText("Θες να επιλέξεις source ως αρχείο (file) ή ως φάκελο (folder);")

        btn_file = msg.addButton("File", QMessageBox.AcceptRole)
        btn_folder = msg.addButton("Folder", QMessageBox.AcceptRole)
        btn_cancel = msg.addButton("Cancel", QMessageBox.RejectRole)

        msg.exec()
        clicked = msg.clickedButton()

        path = ""
        if clicked == btn_file:
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select source file",
                str(Path.home()),
                "All files (*)"
            )
            path = file_path or ""
        elif clicked == btn_folder:
            folder_path = QFileDialog.getExistingDirectory(
                self,
                "Select source folder",
                str(Path.home())
            )
            path = folder_path or ""
        else:
            return

        if path:
            it = self.jobs_table.item(row, 1)
            if it:
                it.setText(path)
            else:
                self.jobs_table.setItem(row, 1, QTableWidgetItem(path))

    def browse_destination(self, row: int):
        path = QFileDialog.getExistingDirectory(self, "Select destination folder")
        if path:
            it = self.jobs_table.item(row, 3)
            if it:
                it.setText(path)
            else:
                self.jobs_table.setItem(row, 3, QTableWidgetItem(path))

    def on_backup_include_changed(self, item: QTableWidgetItem):
        if item.column() != 0:
            return
        row = item.row()
        # κράτα το include_state στο σωστό μέγεθος
        while len(self.include_state) < self.backup_table.rowCount():
            self.include_state.append(False)
        self.include_state[row] = (item.checkState() == Qt.Checked)
        self.update_run_button_state()

    def save_defaults(self):
        # Πάρε το draft από τον πίνακα Ρυθμίσεων και κάν' το saved default
        self.sync_draft_from_settings()
        self.saved_jobs = [
            BackupJob(
                job_id=j.job_id,
                enabled=j.enabled,
                source=j.source,
                destination=j.destination,
                archive_enabled=j.archive_enabled,
                archive_next_seq=j.archive_next_seq,
            )
            for j in self.draft_jobs
        ]
        save_config(self.saved_jobs)

        # Reset session includes από τα saved defaults
        self.include_state = [j.enabled for j in self.saved_jobs]
        self.refresh_backup_from_model()
        self.log("Defaults saved.")

    def create_shortcut(self):
        # Προτείνουμε όνομα αρχείου .cmd
        default_name = "BackupApp_Autorun.cmd"
        start_dir = str(Path.home())

        out_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save shortcut file",
            os.path.join(start_dir, default_name),
            "Command file (*.cmd);;Batch file (*.bat)"
        )
        if not out_path:
            return

        out = Path(out_path)

        # Τι θα τρέξει το shortcut:
        # - Αν είμαστε frozen (PyInstaller): τρέξε το exe με --autorun
        # - Αλλιώς: τρέξε python app.py --autorun (για dev)
        if getattr(sys, "frozen", False):
            exe = Path(sys.executable).resolve()
            cmd_line = f'"{exe}" --autorun'
        else:
            py = Path(sys.executable).resolve()
            script = Path(__file__).resolve()
            cmd_line = f'"{py}" "{script}" --autorun'

        # .cmd που κρατάει σωστό working dir
        content = (
            "@echo off\n"
            "setlocal\n"
            f'cd /d "{app_dir()}"\n'
            f"{cmd_line}\n"
            "endlocal\n"
        )

        try:
            out.write_text(content, encoding="utf-8")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create shortcut.\n\n{e}")
            return

        QMessageBox.information(self, "Shortcut created", f"Created at:\n{out}")

    def start_backup(self):
        if self._thread is not None:
            return

        selected: list[tuple[int, BackupJob]] = []
        for row, job in enumerate(self.saved_jobs):
            if row >= len(self.include_state) or not self.include_state[row]:
                continue
            selected.append((row, job))

        if not selected:
            return

        # --- Pre-flight safety checks (UI thread) ---
        bad = []
        for row, job in selected:
            try:
                if not job.source.strip() or not job.destination.strip():
                    bad.append((row, "Missing source/destination"))
                    continue

                src = Path(job.source).expanduser().resolve()
                dst = Path(job.destination).expanduser().resolve()

                if src.exists() and src.is_dir() and src == dst:
                    bad.append((row, "Source folder equals destination folder"))
                    continue

                if src.exists() and src.is_file():
                    if not job.archive_enabled:
                        target = dst / src.name
                        try:
                            if target.resolve() == src:
                                bad.append((row, "Source file equals destination file"))
                                continue
                        except Exception:
                            pass

            except Exception as e:
                bad.append((row, f"Path error: {e}"))

        if bad:
            text = "Βρέθηκαν μη ασφαλή/λάθος jobs:\n\n" + "\n".join(
                [f"- Job {r+1}: {msg}" for r, msg in bad]
            ) + "\n\nΘες να τα κάνω Skip και να συνεχίσω με τα υπόλοιπα;"
            msg = QMessageBox(self)
            msg.setWindowTitle("Safety check")
            msg.setText(text)
            msg.addButton("Skip bad jobs", QMessageBox.AcceptRole)
            btn_cancel = msg.addButton("Cancel run", QMessageBox.RejectRole)
            msg.exec()

            if msg.clickedButton() == btn_cancel:
                self.log("Run cancelled (safety check).")
                self.run_btn.setEnabled(True)
                return

            bad_rows = {r for r, _ in bad}
            selected = [(r, j) for (r, j) in selected if r not in bad_rows]
            if not selected:
                self.log("No valid jobs to run.")
                self.run_btn.setEnabled(True)
                return

        self._last_summary = None
        self.open_run_log()

        # Reserve archive seq ανά job (UI thread) + αποθήκευση (fallback αν σβηστεί το index)
        run_seq_by_job_id: dict[str, int] = {}
        any_reserved = False
        for _r, j in selected:
            if j.archive_enabled:
                seq = int(j.archive_next_seq) if j.archive_next_seq >= 1 else 1
                run_seq_by_job_id[j.job_id] = seq
                j.archive_next_seq = seq + 1
                any_reserved = True

        if any_reserved:
            try:
                save_config(self.saved_jobs)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save config for archive counter:\n\n{e}")
                self.run_btn.setEnabled(True)
                return

        selected_with_seq: list[tuple[int, BackupJob, int | None]] = [
            (r, j, run_seq_by_job_id.get(j.job_id)) for (r, j) in selected
        ]

        self.run_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.total_progress.setValue(0)
        self.log("=== Run started ===")

        self._thread = QThread(self)
        self._worker = BackupWorker(selected_with_seq)
        self._worker.moveToThread(self._thread)

        self._worker.log.connect(self.log)
        self._worker.progress.connect(self.total_progress.setValue)
        self._worker.row_status.connect(self.set_row_status)

        self._worker.request_create_dest.connect(self.ui_create_dest_dialog)
        self._worker.request_overwrite.connect(self.ui_overwrite_dialog)

        self._worker.summary.connect(self.on_summary)

        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._thread.quit)
        self._thread.finished.connect(self.on_thread_finished)

        self._thread.start()

    @Slot(dict)
    def on_summary(self, data: dict):
        self._last_summary = data

    @Slot(int, str)
    def set_row_status(self, row: int, status: str):
        it = self.backup_table.item(row, 3)
        if it is None:
            it = QTableWidgetItem("")
            self.backup_table.setItem(row, 3, it)
        it.setText(status)

    @Slot(int, str)
    def ui_create_dest_dialog(self, job_row: int, dest_folder: str):
        msg = QMessageBox(self)
        msg.setWindowTitle("Destination δεν υπάρχει")
        msg.setText(f"Ο προορισμός δεν υπάρχει:\n{dest_folder}\n\nΘες να δημιουργηθεί;")

        btn_create = msg.addButton("Create", QMessageBox.AcceptRole)
        btn_skip = msg.addButton("Skip job", QMessageBox.DestructiveRole)
        btn_cancel = msg.addButton("Cancel run", QMessageBox.RejectRole)

        msg.exec()
        clicked = msg.clickedButton()

        if self._worker is None:
            return

        if clicked == btn_create:
            self._worker.reply(Decision.CREATE)
        elif clicked == btn_skip:
            self._worker.reply(Decision.SKIP)
        else:
            self._worker.reply(Decision.CANCEL)

    @Slot(str, str)
    def ui_overwrite_dialog(self, src_file: str, dst_file: str):
        msg = QMessageBox(self)
        msg.setWindowTitle("Overwrite;")
        msg.setText(f"Υπάρχει ήδη αρχείο:\n{dst_file}\n\nΘες overwrite από:\n{src_file}\n;")

        btn_overwrite = msg.addButton("Overwrite", QMessageBox.AcceptRole)
        btn_skip = msg.addButton("Skip", QMessageBox.DestructiveRole)
        btn_overwrite_all = msg.addButton("Overwrite All", QMessageBox.AcceptRole)
        btn_skip_all = msg.addButton("Skip All", QMessageBox.DestructiveRole)
        btn_cancel = msg.addButton("Cancel run", QMessageBox.RejectRole)

        msg.exec()
        clicked = msg.clickedButton()

        if self._worker is None:
            return

        if clicked == btn_overwrite:
            self._worker.reply(Decision.OVERWRITE)
        elif clicked == btn_overwrite_all:
            self._worker.reply(Decision.OVERWRITE_ALL)
        elif clicked == btn_skip_all:
            self._worker.reply(Decision.SKIP_ALL)
        elif clicked == btn_skip:
            self._worker.reply(Decision.SKIP)
        else:
            self._worker.reply(Decision.CANCEL)

    def request_cancel(self):
        if self._worker is not None:
            self.log("Cancel requested...")
            self._worker.cancel()

    def on_thread_finished(self):
        self.log("=== Run ended ===")
        self.run_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)

        # summary μέσα στο log (με ####)
        s = self._last_summary or {}
        cancelled = bool(s.get("cancelled", False))
        elapsed = float(s.get("elapsed_sec", 0.0))

        self.log("########## SUMMARY ##########")
        self.log(f"Cancelled: {'YES' if cancelled else 'NO'}")
        self.log(f"Elapsed: {elapsed:.1f} sec")
        self.log("")
        self.log("Jobs:")
        self.log(f"- Done: {int(s.get('jobs_done', 0))}")
        self.log(f"- Skipped: {int(s.get('jobs_skipped', 0))}")
        self.log(f"- Errors: {int(s.get('jobs_errors', 0))}")
        self.log("")
        self.log("Files:")
        self.log(f"- Total: {int(s.get('files_total', 0))}")
        self.log(f"- Copied: {int(s.get('files_copied', 0))}")
        self.log(f"- Overwritten: {int(s.get('files_overwritten', 0))}")
        self.log(f"- Skipped: {int(s.get('files_skipped', 0))}")
        self.log("########## END SUMMARY ##########")

        self.close_run_log()

        if self._worker is not None:
            self._worker.deleteLater()
        if self._thread is not None:
            self._thread.deleteLater()

        self._worker = None
        self._thread = None

        self.refresh_backup_from_model()


class AutorunWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowIcon(QIcon(str(app_dir() / "app.ico")))

        self.setWindowTitle("BackupApp (Autorun)")
        self.resize(900, 560)

        self.jobs: list[BackupJob] = load_config()

        self._thread: QThread | None = None
        self._worker: BackupWorker | None = None

        self._logs_dir = ensure_hidden_logs_dir()
        self._log_file = None
        self._last_summary: dict | None = None

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        top = QHBoxLayout()
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self.request_cancel)
        top.addWidget(self.cancel_btn)

        self.total_progress = QProgressBar()
        self.total_progress.setRange(0, 100)
        self.total_progress.setValue(0)
        top.addWidget(QLabel("Progress:"))
        top.addWidget(self.total_progress, 1)

        layout.addLayout(top)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        layout.addWidget(QLabel("Log:"))
        layout.addWidget(self.log_box, 1)

        # ξεκίνα αυτόματα
        self.start_autorun()

    def ui_log(self, msg: str):
        self.log_box.append(msg)

    def file_log(self, msg: str):
        if self._log_file:
            try:
                self._log_file.write(msg + "\n")
                self._log_file.flush()
            except Exception:
                pass

    def log(self, msg: str):
        self.ui_log(msg)
        self.file_log(msg)

    def open_run_log(self):
        stamp = time.strftime("%Y%m%d_%H%M%S")
        path = self._logs_dir / f"autorun_{stamp}.log"
        try:
            self._log_file = open(path, "w", encoding="utf-8")
            try:
                FILE_ATTRIBUTE_HIDDEN = 0x2
                ctypes.windll.kernel32.SetFileAttributesW(str(path), FILE_ATTRIBUTE_HIDDEN)
            except Exception:
                pass
        except Exception:
            self._log_file = None

    def close_run_log(self):
        try:
            if self._log_file:
                self._log_file.close()
        except Exception:
            pass
        self._log_file = None

    def request_cancel(self):
        if self._worker is not None:
            self.log("Cancel requested...")
            self._worker.cancel()

    def start_autorun(self):
        # τρέξε ΟΛΑ τα enabled jobs
        selected: list[tuple[int, BackupJob]] = []
        for row, job in enumerate(self.jobs):
            if job.enabled and job.source.strip() and job.destination.strip():
                selected.append((row, job))

        if not selected:
            self.log("No enabled jobs to run.")
            return

        # Pre-flight: ίδιο source/dest μπλοκάρεται (skip)
        bad_rows = set()
        for row, job in selected:
            try:
                src = Path(job.source).expanduser().resolve()
                dst = Path(job.destination).expanduser().resolve()

                if src.exists() and src.is_dir() and src == dst:
                    bad_rows.add(row)
                if src.exists() and src.is_file():
                    if not job.archive_enabled:
                        target = dst / src.name
                        try:
                            if target.resolve() == src:
                                bad_rows.add(row)
                        except Exception:
                            pass
            except Exception:
                bad_rows.add(row)

        if bad_rows:
            self.log("########## SAFETY ##########")
            for r in sorted(bad_rows):
                self.log(f"Skip Job {r+1}: invalid/unsafe paths")
            self.log("########## END SAFETY ##########")
            selected = [(r, j) for (r, j) in selected if r not in bad_rows]
            if not selected:
                self.log("No valid jobs to run after safety checks.")
                return

        self._last_summary = None
        self.open_run_log()

        # Reserve archive seq ανά job + αποθήκευση (fallback αν σβηστεί το index)
        run_seq_by_job_id: dict[str, int] = {}
        any_reserved = False
        for _r, j in selected:
            if j.archive_enabled:
                seq = int(j.archive_next_seq) if j.archive_next_seq >= 1 else 1
                run_seq_by_job_id[j.job_id] = seq
                j.archive_next_seq = seq + 1
                any_reserved = True

        if any_reserved:
            try:
                save_config(self.jobs)
            except Exception as e:
                self.log(f"ERROR: Failed to save config for archive counter: {e}")
                return

        selected_with_seq: list[tuple[int, BackupJob, int | None]] = [
            (r, j, run_seq_by_job_id.get(j.job_id)) for (r, j) in selected
        ]

        self.cancel_btn.setEnabled(True)
        self.total_progress.setValue(0)
        self.log("=== AUTORUN started ===")

        self._thread = QThread(self)
        self._worker = BackupWorker(selected_with_seq)
        self._worker.moveToThread(self._thread)

        self._worker.log.connect(self.log)
        self._worker.progress.connect(self.total_progress.setValue)

        # prompts (destination missing / overwrite) — autorun still asks (ασφαλές)
        self._worker.request_create_dest.connect(self.ui_create_dest_dialog)
        self._worker.request_overwrite.connect(self.ui_overwrite_dialog)

        self._worker.summary.connect(self.on_summary)

        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._thread.quit)
        self._thread.finished.connect(self.on_thread_finished)

        self._thread.start()

    @Slot(dict)
    def on_summary(self, data: dict):
        self._last_summary = data

    @Slot()
    def on_thread_finished(self):
        self.log("=== AUTORUN ended ===")
        self.cancel_btn.setEnabled(False)

        # summary μέσα στο log (με ####)
        s = self._last_summary or {}
        cancelled = bool(s.get("cancelled", False))
        elapsed = float(s.get("elapsed_sec", 0.0))

        self.log("########## SUMMARY ##########")
        self.log(f"Cancelled: {'YES' if cancelled else 'NO'}")
        self.log(f"Elapsed: {elapsed:.1f} sec")
        self.log("")
        self.log("Jobs:")
        self.log(f"- Done: {int(s.get('jobs_done', 0))}")
        self.log(f"- Skipped: {int(s.get('jobs_skipped', 0))}")
        self.log(f"- Errors: {int(s.get('jobs_errors', 0))}")
        self.log("")
        self.log("Files:")
        self.log(f"- Total: {int(s.get('files_total', 0))}")
        self.log(f"- Copied: {int(s.get('files_copied', 0))}")
        self.log(f"- Overwritten: {int(s.get('files_overwritten', 0))}")
        self.log(f"- Skipped: {int(s.get('files_skipped', 0))}")
        self.log("########## END SUMMARY ##########")

        self.close_run_log()

        if self._worker is not None:
            self._worker.deleteLater()
        if self._thread is not None:
            self._thread.deleteLater()

        self._worker = None
        self._thread = None

    @Slot(int, str)
    def ui_create_dest_dialog(self, job_row: int, dest_folder: str):
        msg = QMessageBox(self)
        msg.setWindowTitle("Destination δεν υπάρχει")
        msg.setText(f"Ο προορισμός δεν υπάρχει:\n{dest_folder}\n\nΘες να δημιουργηθεί;")

        btn_create = msg.addButton("Create", QMessageBox.AcceptRole)
        btn_skip = msg.addButton("Skip job", QMessageBox.DestructiveRole)
        btn_cancel = msg.addButton("Cancel run", QMessageBox.RejectRole)

        msg.exec()
        clicked = msg.clickedButton()

        if self._worker is None:
            return

        if clicked == btn_create:
            self._worker.reply(Decision.CREATE)
        elif clicked == btn_skip:
            self._worker.reply(Decision.SKIP)
        else:
            self._worker.reply(Decision.CANCEL)

    @Slot(str, str)
    def ui_overwrite_dialog(self, src_file: str, dst_file: str):
        msg = QMessageBox(self)
        msg.setWindowTitle("Overwrite;")
        msg.setText(f"Υπάρχει ήδη αρχείο:\n{dst_file}\n\nΘες overwrite από:\n{src_file}\n;")

        btn_overwrite = msg.addButton("Overwrite", QMessageBox.AcceptRole)
        btn_skip = msg.addButton("Skip", QMessageBox.DestructiveRole)
        btn_overwrite_all = msg.addButton("Overwrite All", QMessageBox.AcceptRole)
        btn_skip_all = msg.addButton("Skip All", QMessageBox.DestructiveRole)
        btn_cancel = msg.addButton("Cancel run", QMessageBox.RejectRole)

        msg.exec()
        clicked = msg.clickedButton()

        if self._worker is None:
            return

        if clicked == btn_overwrite:
            self._worker.reply(Decision.OVERWRITE)
        elif clicked == btn_overwrite_all:
            self._worker.reply(Decision.OVERWRITE_ALL)
        elif clicked == btn_skip_all:
            self._worker.reply(Decision.SKIP_ALL)
        elif clicked == btn_skip:
            self._worker.reply(Decision.SKIP)
        else:
            self._worker.reply(Decision.CANCEL)


def main():
    app = QApplication(sys.argv)
    install_crash_handler()

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--autorun", action="store_true")
    args, _ = parser.parse_known_args()

    if args.autorun:
        w = AutorunWindow()
    else:
        w = MainWindow()

    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

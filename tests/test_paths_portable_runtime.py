from pathlib import Path

import modules.paths as paths


def test_frozen_state_root_is_always_exe_directory(monkeypatch, tmp_path: Path):
    exe_dir = tmp_path / "dist"
    exe_dir.mkdir()
    exe = exe_dir / "ApplicationSplitRouting.exe"
    exe.write_bytes(b"")

    monkeypatch.setattr(paths.sys, "frozen", True, raising=False)
    monkeypatch.setattr(paths.sys, "executable", str(exe))

    root = paths.state_root()
    assert root == exe_dir.resolve()
    assert (exe_dir / "runtime").is_dir()

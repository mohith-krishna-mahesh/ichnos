"""Docker and OCI Container Image Layer Forensics.

Extracts container tarballs, inspects manifest.json, diffs layer states,
and recovers deleted files hidden by OCI whiteout markers (.wh.<filename>).
"""

from __future__ import annotations

import io
import json
import tarfile
from typing import Any

from ichnos.core.security import DEFAULT_MAX_DECOMPRESSED_SIZE, sanitize_archive_path


def inspect_container_image(image_tar_data: bytes) -> dict[str, Any]:
    """Inspects an exported Docker/OCI image archive (tar format).

    Args:
        image_tar_data: Raw bytes of the image tar archive.

    Returns:
        Dict with: 'manifest', 'layers_count', 'deleted_files', 'recovered_layer_files'.
    """
    manifest: list[dict[str, Any]] = []
    layer_tar_names: list[str] = []

    try:
        with tarfile.open(fileobj=io.BytesIO(image_tar_data), mode="r:*") as tar:
            # Locate manifest.json
            for member in tar.getmembers():
                if member.name == "manifest.json":
                    f = tar.extractfile(member)
                    if f:
                        manifest = json.loads(f.read(10 * 1024 * 1024).decode("utf-8"))
                        if manifest and isinstance(manifest, list):
                            layer_tar_names = manifest[0].get("Layers", [])
                        break

            # If no manifest, list all tar members ending with layer.tar
            if not layer_tar_names:
                layer_tar_names = [m.name for m in tar.getmembers() if m.name.endswith(".tar")]

            # Track files across layers
            # filename -> dict of {'created_in_layer': idx, 'data': bytes, 'deleted_in_layer': idx | None}
            file_history: dict[str, dict[str, Any]] = {}
            whiteouts: list[dict[str, Any]] = []

            for layer_idx, layer_name in enumerate(layer_tar_names[:64]):
                try:
                    layer_member = tar.getmember(layer_name)
                    layer_file = tar.extractfile(layer_member)
                    if not layer_file:
                        continue
                    layer_bytes = layer_file.read(DEFAULT_MAX_DECOMPRESSED_SIZE + 1)
                    if len(layer_bytes) > DEFAULT_MAX_DECOMPRESSED_SIZE:
                        continue
                    with tarfile.open(fileobj=io.BytesIO(layer_bytes), mode="r:*") as ltar:
                        for lmem in ltar.getmembers():
                            try:
                                name = sanitize_archive_path(lmem.name)
                            except ValueError:
                                continue
                            base_name = name.split("/")[-1]

                            # Check for OCI whiteout marker (.wh.<filename>)
                            if base_name.startswith(".wh.") and base_name != ".wh..wh..opq":
                                deleted_target = base_name[4:]
                                target_path = (
                                    "/".join(name.split("/")[:-1] + [deleted_target])
                                    if "/" in name
                                    else deleted_target
                                )
                                whiteouts.append({
                                    "layer_index": layer_idx,
                                    "layer_name": layer_name,
                                    "deleted_path": target_path,
                                })
                                if target_path in file_history:
                                    file_history[target_path]["deleted_in_layer"] = layer_idx
                            elif lmem.isreg():
                                try:
                                    f_data = ltar.extractfile(lmem)
                                    content = f_data.read(16 * 1024 * 1024) if f_data else b""
                                    file_history[name] = {
                                        "layer_index": layer_idx,
                                        "size": len(content),
                                        "data": content,
                                        "deleted_in_layer": None,
                                    }
                                except Exception:
                                    pass
                except Exception:
                    continue

    except Exception as e:
        return {"error": f"Failed to parse container archive: {e}"}

    # Identify files that were deleted in upper layers
    deleted_recoveries: list[dict[str, Any]] = []
    for wh in whiteouts:
        target = wh["deleted_path"]
        if target in file_history:
            entry = file_history[target]
            preview = ""
            try:
                preview = entry["data"].decode("utf-8", errors="ignore")[:100]
            except Exception:
                pass
            deleted_recoveries.append({
                "path": target,
                "created_in_layer": entry["layer_index"],
                "deleted_in_layer": wh["layer_index"],
                "size": entry["size"],
                "preview": preview,
            })

    return {
        "layers_count": len(layer_tar_names),
        "whiteout_markers_count": len(whiteouts),
        "deleted_files": deleted_recoveries,
        "total_unique_files": len(file_history),
    }

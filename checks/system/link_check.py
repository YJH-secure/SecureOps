"""Bounded read-only target inspection. Limits are collection scope, not approval policy."""
import os
import stat


def inspect_link(path, initial, collect_target, max_hops=8, inspection_root='/etc'):
    chain, seen = [], set()
    snapshots = []
    current, info = os.path.abspath(path), initial
    root = os.path.realpath(inspection_root)
    def inside(candidate):
        try:
            return os.path.commonpath((root, candidate)) == root
        except ValueError:
            return False
    try:
        for hop in range(max_hops + 1):
            if current in seen:
                return dict(state='error', reason='symlink_cycle', chain=chain)
            seen.add(current)
            snapshots.append((current, tuple(getattr(info, k, None) for k in
                             ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_ctime_ns'))))
            if not stat.S_ISLNK(info.st_mode):
                canonical = os.path.realpath(current)
                if not inside(canonical):
                    return dict(state='needs_review', reason='target_outside_inspection_scope', chain=chain)
                target = collect_target(current)
                if target.get('file_type') != 'regular' or target.get('snapshot_error'):
                    return dict(state='error', reason='target_not_regular_or_changed', chain=chain,
                                target_observation=target)
                for checked_path, expected in snapshots:
                    after = os.lstat(checked_path)
                    if tuple(getattr(after, k, None) for k in
                             ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_ctime_ns')) != expected:
                        return dict(state='error', reason='link_chain_changed', chain=chain,
                                    target_observation=target)
                return dict(state='collected', reason='target_inspected_not_automatically_approved',
                            chain=chain, target_path=canonical, target_observation=target)
            if hop == max_hops:
                return dict(state='error', reason='symlink_hop_limit', chain=chain)
            raw = os.readlink(current)
            next_path = os.path.normpath(raw if os.path.isabs(raw) else os.path.join(os.path.dirname(current), raw))
            chain.append(dict(link=current, target_text=raw, next_path=next_path))
            # Resolve parent-directory aliases before touching the next node.
            parent = os.path.realpath(os.path.dirname(next_path))
            if not inside(parent) or not inside(os.path.join(parent, os.path.basename(next_path))):
                return dict(state='needs_review', reason='target_outside_inspection_scope', chain=chain)
            current = os.path.join(parent, os.path.basename(next_path))
            info = os.lstat(current)
    except OSError as exc:
        return dict(state='error', reason='target_lookup_failed', detail=str(exc), chain=chain)


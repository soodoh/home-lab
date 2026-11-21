"""Interpret native Restic snapshot metadata without making admission decisions."""

DAILY = 'cadence=daily'
FULL = 'format=full-v2'
COMPLETE = 'complete=full-v2'


def tags(snapshot):
    values = snapshot.get('tags')
    if values is None:  # Restic may serialize an empty tag list as null.
        return set()
    if not isinstance(values, list) or any(not isinstance(tag, str) for tag in values):
        raise ValueError('snapshot_tags')
    return set(values)


def format_tags(snapshot_tags):
    return {tag for tag in snapshot_tags if tag.startswith('format=')}


def daily_kind(snapshot_tags):
    if DAILY not in snapshot_tags:
        return None
    formats = format_tags(snapshot_tags)
    if not formats:
        return 'legacy'
    if formats == {FULL} and COMPLETE in snapshot_tags:
        return 'complete'
    return None


def same_copy(source, candidate):
    # Retagging rewrites the snapshot ID. Copy preserves the earliest original ID.
    return (candidate.get('original') == source.get('original', source['id'])
            and tags(candidate) == tags(source)
            and all(candidate.get(key) == source.get(key) for key in ('time', 'tree', 'paths')))

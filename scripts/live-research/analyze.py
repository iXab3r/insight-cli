#!/usr/bin/env python3
"""Retrospective public-CLI timing analysis. Reads receipts; never invokes the product.

Usage: python3 scripts/live-research/analyze.py <private-run-directory> <output.json>
Only portable timing aggregates and sanitized errors are emitted. Raw replies/selectors stay private.
"""
import collections
import hashlib
import json
import statistics
import sys
from pathlib import Path

run = Path(sys.argv[1])
load = lambda path: json.loads(path.read_text())
ns = lambda stamp: int(stamp['monotonicNs'])
def seconds(a, b):
    return (ns(b) - ns(a)) / 1e9

def union_seconds(intervals):
    total = 0
    end = None
    for first, last in sorted(intervals):
        assert last >= first
        if end is None or first > end:
            total += last - first
        else:
            total += max(0, last - end)
        end = max(end or last, last)
    return total / 1e9

def summary(values):
    ordered = sorted(values)
    return {'count': len(values), 'sumSeconds': sum(values),
            'medianSeconds': statistics.median(values),
            'p95NearestRankSeconds': ordered[max(0, (95 * len(values) + 99) // 100 - 1)],
            'maxSeconds': max(values)}

def command_name(args):
    return ' '.join(args[:3] if args[0] == 'ghidra' else args[:2])

trials = []
source_hashes = {}
for folder in sorted(run.iterdir()):
    if not folder.name.startswith(('pair-', 'cold-')) or not (folder/'trial.json').exists():
        continue
    t = load(folder/'trial.json')
    events_path = folder/'events.jsonl'
    if not events_path.exists():
        continue
    source_hashes[folder.name+'/trial.json'] = hashlib.sha256((folder/'trial.json').read_bytes()).hexdigest()
    source_hashes[folder.name+'/events.jsonl'] = hashlib.sha256(events_path.read_bytes()).hexdigest()
    events = [json.loads(line) for line in events_path.read_text().splitlines()]
    calls = []
    for file in sorted((folder/'actors').glob('*/*/commands.jsonl')):
        # Preserve only research, save and the original lead collection; setup/cleanup and
        # recovery are different clock scopes. A failed collection is retained as incomplete.
        actor, role = file.parent.parent.name, file.parent.name.split('-')[0]
        if not (actor.isdigit() and role in ('read', 'save') or actor == 'lead' and role == 'collect'):
            continue
        source_hashes[file.relative_to(run).as_posix()] = hashlib.sha256(file.read_bytes()).hexdigest()
        for line in file.read_text().splitlines():
            c = json.loads(line)
            stderr = (file.parent/(str(c['n'])+'.stderr')).read_text()
            error = None
            if c['code']:
                try:
                    value = json.loads(stderr)['error']
                    error = {key: value[key] for key in ('code', 'message') if key in value}
                except (ValueError, KeyError):
                    error = {'code': 'unparsed_error'}
            calls.append({'actor': actor, 'role': role, 'sequence': c['n'],
                          'command': command_name(c['args']), 'durationSeconds': (c['ended']-c['started'])/1000,
                          'code': c['code'], 'error': error,
                          'responseBytes': (file.parent/(str(c['n'])+'.stdout')).stat().st_size,
                          'address': c['args'][c['args'].index('--address')+1] if '--address' in c['args'] else None})
    reads = [event for event in events if event['state'] == 'read']
    saved = [event for event in events if event['state'] == 'finding-saved']
    first = min(reads, key=lambda e: ns(e['started']))['started']
    last = max(saved, key=lambda e: ns(e['at']))['at']
    read_union = union_seconds([(ns(e['started']), ns(e['ended'])) for e in reads])
    actors = []
    for actor in range(t['workers']):
        ar = sorted([e for e in reads if int(e['actor']) == actor], key=lambda e: ns(e['started']))
        done = sorted([e for e in saved if int(e['actor']) == actor], key=lambda e: ns(e['at']))
        ac = [c for c in calls if c['actor'] == str(actor)]
        failed = [c for c in ac if c['code']]
        save_sum = sum(c['durationSeconds'] for c in ac if c['role'] == 'save')
        failed_sum = sum(c['durationSeconds'] for c in failed)
        after_read = seconds(ar[-1]['ended'], done[-1]['at'])
        # Subtract ALL timed save and failed-read calls, even if they happened earlier.
        # Concurrent calls make this a conservative lower bound, not a wall partition.
        outside_lower = max(0, seconds(t['dispatched'], done[-1]['at']) - sum(c['durationSeconds'] for c in ac))
        addresses = collections.Counter((c['command'], c['address']) for c in ac if c['role'] == 'read' and c['address'])
        actors.append({'actor': actor, 'parts': [e['part'] for e in done],
                       'firstSuccessfulReadStartSeconds': seconds(t['dispatched'], ar[0]['started']),
                       'lastSuccessfulReadEndSeconds': seconds(t['dispatched'], ar[-1]['ended']),
                       'lastFindingSavedSeconds': seconds(t['dispatched'], done[-1]['at']),
                       'successfulReadEnvelopeUnionSeconds': union_seconds([(ns(e['started']), ns(e['ended'])) for e in ar]),
                       'allCliServiceSumSeconds': sum(c['durationSeconds'] for c in ac),
                       'saveCliServiceSumSeconds': save_sum,
                       'outsideTimedCliLowerBoundSeconds': outside_lower,
                       'afterLastSuccessfulReadSeconds': after_read,
                       'afterLastSuccessfulReadOutsideTimedCliLowerBoundSeconds': max(0, after_read-save_sum-failed_sum),
                       'readAttempts': sum(c['role'] == 'read' for c in ac), 'successfulReadEvents': len(ar),
                       'failedCalls': failed, 'readResponseBytes': sum(c['responseBytes'] for c in ac if c['role'] == 'read'),
                       'repeatedAddressReads': [{'command': cmd, 'address': addr, 'count': count} for (cmd, addr), count in addresses.items() if count > 1]})
    item = {'name': t['name'], 'workers': t['workers'], 'state': t['state'], 'cold': t['cold'],
            'actors': actors, 'researchCalls': [c for c in calls if c['actor'].isdigit()],
            'successfulReadEnvelopeUnionSeconds': read_union,
            'firstSuccessfulReadStartSeconds': seconds(t['dispatched'], first),
            'lastFindingSavedSeconds': seconds(t['dispatched'], last),
            'leadCalls': sorted([c for c in calls if c['actor'] == 'lead'], key=lambda c: c['sequence'])}
    if t['state'] == 'passed':
        reader = next(c for c in item['leadCalls'] if c['command'] == 'ghidra open --target')
        # Exclusive monotonic partition: no overlapping per-agent durations are added here.
        item['wallPartition'] = {
            'beforeDispatchSeconds': seconds(t['started'], t['dispatched']),
            'dispatchToFirstSuccessfulReadSeconds': seconds(t['dispatched'], first),
            'successfulResearchReadEnvelopeUnionSeconds': read_union,
            'otherResearchWindowSeconds': seconds(first, last)-read_union,
            'lastSaveToCollectionStartSeconds': seconds(last, t['researchFinished']),
            'collectionSeconds': t['phases']['collectionSeconds'],
            'mergeSeconds': t['phases']['mergeSeconds'],
            'freshReaderOpenCliSeconds': reader['durationSeconds'],
            'remainingIndependentVerificationSeconds': t['phases']['independentVerificationSeconds']-reader['durationSeconds'],
            'semanticReviewAndFinishSeconds': t['phases']['semanticReviewSeconds']}
        item['elapsedSeconds'] = t['elapsedSeconds']
        assert abs(sum(item['wallPartition'].values())-t['elapsedSeconds']) < 1e-6
        item['afterResearchSeconds'] = seconds(t['researchFinished'], t['finished'])
        critical = max(actors, key=lambda a: a['lastFindingSavedSeconds'])
        item['criticalActor'] = critical['actor']
        item['earlierActorIdleUntilLastSaveSeconds'] = {str(a['actor']): item['lastFindingSavedSeconds']-a['lastFindingSavedSeconds'] for a in actors}
        item['nativeCpuSecondsAcrossObserverWindow'] = sum(t['nativeProof']['cpuAfter'][pid]-value for pid, value in t['nativeProof']['cpuBefore'].items())
    trials.append(item)

completed_prepared = [t for t in trials if t['state'] == 'passed' and not t['cold']]
latencies = collections.defaultdict(list)
for t in completed_prepared:
    for c in t['researchCalls']:
        latencies[c['command']].append(c['durationSeconds'])
result = {'schema': 1, 'source': 'Retrospective analysis of the unchanged 2026-10-16 live-agent run.',
          'timingSemantics': {
              'wallPartition': 'Exclusive monotonic clock intervals, sum equals original endpoint. Successful reads use the union across all actors, never summed overlapping durations.',
              'cliServiceSum': 'Client-observed subprocess latency including CLI/IPC/native/network/keyring/OS work. Sums are workload costs, not a wall-clock partition; subprocess calls can overlap.',
              'otherResearchWindow': 'Everything between first successful read and last save outside successful read envelopes: reasoning/provider/tool dispatch, formatting/file writes, save calls, failed reads and waits. These cannot be separated retrospectively.',
              'outsideTimedCliLowerBound': 'Elapsed actor window minus every timed CLI call duration; conservative with overlap. This is NOT a model inference duration.',
              'failedReadVisibility': 'Original events.jsonl logs successful reads only. Failed reads recovered from commands.jsonl have precise latency but no absolute start timestamp.',
              'cpuWindow': 'Native worker CPU accumulated from observer start until merge completion; not pure research CPU or native elapsed time.'},
          'preparedResearchCliLatency': {k: summary(v) for k, v in sorted(latencies.items())},
          'trials': trials, 'sourceReceiptSha256': source_hashes}
Path(sys.argv[2]).write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps({'trials': len(trials), 'exclusivePartitionsValidated': sum('wallPartition' in t for t in trials), 'receiptHashes': len(source_hashes)}))

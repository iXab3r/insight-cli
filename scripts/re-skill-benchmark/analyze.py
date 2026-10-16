#!/usr/bin/env python3
"""Offline live RE-skill benchmark analyzer (Python standard library only).

Usage: python3 scripts/re-skill-benchmark/analyze.py RUN [--output REPORT.json]
Reads existing receipts only. It never invokes a CLI or native process. Output is
portable JSON; input filenames and exception text are deliberately not reported.
All interval arithmetic uses integer monotonic nanoseconds, never UTC timestamps.
"""

import argparse
import json
import math
import re
import statistics
import sys
from pathlib import Path

NS = 1_000_000_000
EXPECTED = ["pair-1-1", "pair-1-3", "pair-2-3", "pair-2-1", "pair-3-1", "pair-3-3"]
CLI_CATEGORIES = {"setup", "read", "annotation", "artifacts", "collection", "merge", "verification", "summary"}


def ns(value):
    if isinstance(value, dict):
        value = value.get("monotonicNs")
    if isinstance(value, bool) or value is None:
        raise ValueError("invalid timestamp")
    return int(value)


def duration(value):
    return {"ns": str(value), "seconds": value / NS}


def portable(value):
    """Defense in depth: never propagate private receipt paths into the report."""
    if isinstance(value, dict):
        return {portable(str(k)): portable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [portable(v) for v in value]
    if isinstance(value, str):
        return re.sub(r"/(?:Users|private)(?:/[^\s\"'<>;,]*)?", "[private-path]", value)
    return value


def union(intervals):
    result = []
    for start, end in sorted((a, b) for a, b in intervals if b > a):
        if result and start <= result[-1][1]:
            result[-1] = (result[-1][0], max(end, result[-1][1]))
        else:
            result.append((start, end))
    return result


def clipped(intervals, start, end):
    return union((max(a, start), min(b, end)) for a, b in intervals)


def total(intervals):
    return sum(b - a for a, b in union(intervals))


def complement(intervals, start, end):
    result, cursor = [], start
    for a, b in clipped(intervals, start, end):
        if a > cursor:
            result.append((cursor, a))
        cursor = b
    if cursor < end:
        result.append((cursor, end))
    return result


def interval_report(intervals, origin):
    normalized = union(intervals)
    return {"duration": duration(total(normalized)), "intervals": [
        {"startOffsetNs": str(a - origin), "endOffsetNs": str(b - origin)} for a, b in normalized
    ]}


def stats(values):
    values = sorted(values)
    if not values:
        return {"count": 0, "medianSeconds": None, "p95Seconds": None, "maxSeconds": None}
    return {"count": len(values), "medianSeconds": statistics.median(values) / NS,
            "p95Seconds": values[math.ceil(.95 * len(values)) - 1] / NS,
            "maxSeconds": values[-1] / NS}


def describe(values):
    return {"n": len(values), "median": statistics.median(values) if values else None,
            "min": min(values) if values else None, "max": max(values) if values else None}


def read_json(path):
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def read_events(path, warnings):
    events = []
    if not path.exists():
        warnings.append("events_missing")
        return [], []
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                event["time"] = ns(event["at"])
                event["actor"] = str(event.get("actor", "unknown"))
                events.append(event)
            except (ValueError, TypeError, KeyError):
                warnings.append("invalid_event_line_" + str(number))
    starts, spans, markers = {}, [], []
    for event in sorted(events, key=lambda e: e["time"]):
        if event.get("phase") == "point":
            markers.append(event)
            continue
        key = (event["actor"], str(event.get("id")))
        if event.get("phase") == "start":
            if key in starts:
                warnings.append("duplicate_span_start")
            starts[key] = event
        elif event.get("phase") == "end":
            start = starts.pop(key, None)
            if start is None:
                warnings.append("unmatched_span_end")
                continue
            if event["time"] < start["time"]:
                warnings.append("negative_span")
                continue
            spans.append({"actor": start["actor"], "category": start.get("category"),
                          "operation": start.get("operation", "unknown"),
                          "start": start["time"], "end": event["time"],
                          "ok": event.get("ok"), "code": event.get("code")})
    if starts:
        warnings.append("unmatched_span_starts_" + str(len(starts)))
    return spans, markers


def command_stats(spans):
    groups = {}
    for span in spans:
        key = str(span["category"]) + ":" + str(span["operation"])
        groups.setdefault(key, []).append(span)
    def one(items):
        result = stats([s["end"] - s["start"] for s in items])
        result.update({"failed": sum(s["ok"] is False for s in items),
                       "unknownOutcome": sum(s["ok"] is None for s in items),
                       "failureCodes": {}})
        for span in items:
            if span["ok"] is False:
                code = str(span.get("code") or "unspecified")
                result["failureCodes"][code] = result["failureCodes"].get(code, 0) + 1
        return result
    return {"all": one(spans), "byOperation": {key: one(items) for key, items in sorted(groups.items())}}


def cpu_proof(directory, trial, warnings):
    """CPU is process CPU growth, not a decomposition of model inference time."""
    proof = trial.get("nativeProof", {})
    result = {"recorded": proof}
    window = proof.get("commonWindow", {}) if isinstance(proof, dict) else {}
    try:
        start, end = ns(window["first"]), ns(window["last"])
    except (KeyError, ValueError, TypeError):
        result["derived"] = None
        return result
    pids = [str(item["pid"]) for item in trial.get("native", []) if isinstance(item, dict) and "pid" in item]
    samples = []
    path = directory / "native-observations.jsonl"
    if path.exists():
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                try:
                    row = json.loads(line)
                    at = ns(row)
                    if start <= at <= end:
                        samples.append((at, row.get("cpu", {})))
                except (ValueError, TypeError, KeyError):
                    warnings.append("invalid_cpu_sample")
    samples.sort(key=lambda item: item[0])
    growth = {}
    for pid in pids:
        valid = [(at, cpu[pid]["cpuSeconds"] if isinstance(cpu[pid], dict) else cpu[pid])
                 for at, cpu in samples if isinstance(cpu, dict) and pid in cpu]
        if len(valid) >= 2:
            delta = float(valid[-1][1]) - float(valid[0][1])
            growth[pid] = {"cpuSeconds": delta, "sampleWindow": duration(valid[-1][0] - valid[0][0]), "grew": delta > 0}
        else:
            growth[pid] = {"cpuSeconds": None, "grew": None}
    result["derived"] = {"commonWindow": duration(end - start), "perPid": growth,
                         "allWorkersCpuGrew": bool(pids) and all(growth[p]["grew"] is True for p in pids)}
    return result


def analyze_trial(directory, trial):
    warnings = []
    spans, markers = read_events(directory / "events.jsonl", warnings)
    cli = [s for s in spans if s["category"] in CLI_CATEGORIES]
    stamps = {key: ns(trial[key]) for key in ("dispatched", "researchFinished", "collected", "merged", "verified", "finished")}
    ordered = list(stamps.values())
    if ordered != sorted(ordered):
        raise ValueError("stage timestamps are not monotonic")
    origin, research_end, finished = stamps["dispatched"], stamps["researchFinished"], stamps["finished"]
    configured = trial.get("workers")
    if isinstance(configured, list):
        actors = [str(a.get("actor", a.get("id"))) if isinstance(a, dict) else str(a) for a in configured]
        worker_count = len(actors)
    else:
        worker_count = int(configured)
        actors = [str(i) for i in range(worker_count)]
    by_actor = {actor: [m for m in markers if m["actor"] == actor] for actor in actors}
    done = {actor: max((m["time"] for m in by_actor[actor] if m.get("operation") == "done"), default=None) for actor in actors}
    complete_done = all(value is not None for value in done.values())
    final_done = max(done.values()) if complete_done and done else research_end
    if not complete_done:
        warnings.append("worker_done_markers_missing_researchFinished_used")
    if final_done < origin or final_done > research_end:
        warnings.append("done_outside_research_window_clamped")
        final_done = max(origin, min(research_end, final_done))
    research_calls = [s for s in cli if s["actor"] in actors and s["category"] in {"read", "annotation", "artifacts"}]
    reads = [s for s in research_calls if s["category"] == "read" and s["start"] < final_done and s["end"] >= origin]
    first_read = max(origin, min((s["start"] for s in reads), default=origin))
    if not reads:
        warnings.append("no_research_read_dispatch_used")
    buckets, pieces = {}, []
    def add(label, start, end):
        if end < start:
            raise ValueError("negative partition")
        buckets[label] = buckets.get(label, 0) + end - start
        if end > start:
            pieces.append({"category": label, "startOffsetNs": str(start - origin), "endOffsetNs": str(end - origin), "durationNs": str(end - start)})
    add("dispatch_to_first_read", origin, first_read)
    active = clipped([(s["start"], s["end"]) for s in research_calls], first_read, final_done)
    points = {first_read, final_done}
    for span in research_calls:
        a, b = max(first_read, span["start"]), min(final_done, span["end"])
        if b > a:
            points.update((a, b))
    points = sorted(points)
    for a, b in zip(points, points[1:]):
        categories = {s["category"] for s in research_calls if s["start"] < b and s["end"] > a}
        # Explicit deterministic tie break; annotation and artifacts outrank reads.
        category = next((c for c in ("artifacts", "annotation", "read") if c in categories), "outside_cli")
        add("research_" + category, a, b)
    add("handoff_after_final_done", final_done, research_end)
    add("collection", research_end, stamps["collected"])
    add("merge", stamps["collected"], stamps["merged"])
    for label, category, operation, start, end in [
        ("verification", "verification", "fresh-open", stamps["merged"], stamps["verified"]),
        ("semantic_review", "summary", None, stamps["verified"], finished),
    ]:
        selected = clipped([(s["start"], s["end"]) for s in cli if s["category"] == category and (operation is None or s["operation"] == operation)], start, end)
        special = "verification_fresh_open" if label == "verification" else "summary_save"
        rest = "verification_rest" if label == "verification" else "semantic_review_outside_summary"
        for a, b in selected:
            add(special, a, b)
        for a, b in complement(selected, start, end):
            add(rest, a, b)
        buckets.setdefault(special, 0)
        buckets.setdefault(rest, 0)
    for category in ("read", "annotation", "artifacts", "outside_cli"):
        buckets.setdefault("research_" + category, 0)
    expected_ns = finished - origin
    assert sum(buckets.values()) == expected_ns
    actor_reports = {}
    for actor in actors:
        actor_done = done[actor] if done[actor] is not None else final_done
        actor_done = max(origin, min(research_end, actor_done))
        actor_spans = [s for s in cli if s["actor"] == actor]
        actor_research = [s for s in actor_spans if s["category"] in {"read", "annotation", "artifacts"}]
        actor_reads = [s for s in actor_research if s["category"] == "read"]
        intervals = clipped([(s["start"], s["end"]) for s in actor_research], origin, actor_done)
        writing = {}
        for marker in by_actor[actor]:
            operation = marker.get("operation", "")
            if operation.startswith("writing:"):
                part = operation.split(":", 1)[1]
                ends = [m["time"] for m in by_actor[actor] if m.get("operation") == "written:" + part and m["time"] >= marker["time"]]
                writing.setdefault(part, []).append((marker["time"], min(ends))) if ends else warnings.append("unmatched_writing_marker_actor_" + actor)
        first = min((s["start"] for s in actor_reads), default=None)
        last = max((s["end"] for s in actor_reads), default=None)
        actor_reports[actor] = {
            "firstReadOffset": duration(first - origin) if first is not None else None,
            "finalDoneOffset": duration(actor_done - origin) if done[actor] is not None else None,
            "researchCliUnion": interval_report(intervals, origin),
            "researchCliSum": duration(sum(max(0, min(s["end"], actor_done) - max(s["start"], origin)) for s in actor_research)),
            "outsideResearchCli": interval_report(complement(intervals, origin, actor_done), origin),
            "postLastReadToDone": duration(max(0, actor_done - last)) if last is not None else None,
            "writingMarkers": {part: interval_report(values, origin) for part, values in sorted(writing.items())},
            "idleTailToFinalDone": duration(max(0, final_done - actor_done)),
            "doneToCollectionTrigger": duration(research_end - actor_done),
            "commands": command_stats(actor_spans),
        }
    report = {"name": directory.name, "workers": worker_count, "state": trial.get("state", "unknown"),
              "cleanupComplete": trial.get("cleanupComplete", False), "task": duration(expected_ns),
              "preparedResearch": duration(research_end - origin),
              "activeResearch": duration(final_done - origin),
              "partition": {"exact": True, "total": duration(sum(buckets.values())),
                            "buckets": {k: duration(v) for k, v in sorted(buckets.items())},
                            "intervals": sorted(pieces, key=lambda p: int(p["startOffsetNs"]))},
              "actors": actor_reports, "commands": command_stats(cli),
              "researchCliWallUnion": duration(total(active)),
              "researchCliSummedAcrossWorkers": duration(sum(max(0, min(s["end"], final_done) - max(s["start"], first_read)) for s in research_calls)),
              "nativeCpu": cpu_proof(directory, trial, warnings), "warnings": warnings}
    for key, start, end in [("setup", "setupStarted", "ready"), ("preparedOpen", "firstOpenStarted", "ready")]:
        if start in trial and end in trial:
            report[key] = duration(ns(trial[end]) - ns(trial[start]))
    report["eligibleForSpeedup"] = report["state"] == "passed" and report["cleanupComplete"] is True and not warnings
    return report


def compare(reports):
    by_name = {r["name"]: r for r in reports}
    pairs = []
    for number in range(1, 4):
        one, three = by_name.get(f"pair-{number}-1"), by_name.get(f"pair-{number}-3")
        entry = {"pair": number, "oneWorkerState": one.get("state") if one else "missing", "threeWorkerState": three.get("state") if three else "missing"}
        entry["eligible"] = bool(one and three and one.get("eligibleForSpeedup") and three.get("eligibleForSpeedup"))
        for metric in ("task", "preparedResearch", "activeResearch"):
            if entry["eligible"] and three[metric]["seconds"] > 0:
                entry[metric + "Speedup"] = one[metric]["seconds"] / three[metric]["seconds"]
            else:
                entry[metric + "Speedup"] = None
        pairs.append(entry)
    return {"pairs": pairs, "pairedTaskSpeedup": describe([p["taskSpeedup"] for p in pairs if p["taskSpeedup"] is not None]),
            "pairedPreparedResearchSpeedup": describe([p["preparedResearchSpeedup"] for p in pairs if p["preparedResearchSpeedup"] is not None]),
            "allThreeWorkerTrials": [{"name": r["name"], "state": r.get("state"), "eligible": r.get("eligibleForSpeedup", False), "task": r.get("task")} for r in reports if r.get("workers") == 3 or r["name"] in {"pair-1-3", "pair-2-3", "pair-3-3"}],
            "successfulThreeWorkerTaskSeconds": describe([r["task"]["seconds"] for r in reports if r.get("workers") == 3 and r.get("eligibleForSpeedup")])}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        manifest = read_json(args.run / "manifest.json")
    except (OSError, ValueError):
        print(json.dumps({"schema": 1, "error": "manifest_missing_or_invalid"}))
        return 2
    reports = []
    names = list(EXPECTED)
    names.extend(sorted(p.name for p in args.run.iterdir() if p.is_dir() and (p / "trial.json").exists() and p.name not in names))
    for name in names:
        trial = {}
        try:
            trial = read_json(args.run / name / "trial.json")
            reports.append(analyze_trial(args.run / name, trial))
        except (OSError, ValueError, TypeError, KeyError, AssertionError, OverflowError):
            partial_warnings = []
            try:
                partial_spans, _ = read_events(args.run / name / "events.jsonl", partial_warnings)
                partial_commands = command_stats([s for s in partial_spans if s["category"] in CLI_CATEGORIES])
            except (OSError, ValueError, TypeError):
                partial_commands = None
            reports.append({"name": name, "state": trial.get("state", "missing_or_invalid"), "workers": trial.get("workers"),
                            "cleanupComplete": trial.get("cleanupComplete", False), "eligibleForSpeedup": False,
                            "error": "trial_missing_incomplete_or_invalid", "nativeProof": trial.get("nativeProof"),
                            "commands": partial_commands, "warnings": partial_warnings,
                            "timingFieldsPresent": [k for k in ("setupStarted", "ready", "dispatched", "researchFinished", "collected", "merged", "verified", "finished") if k in trial]})
    report = {"schema": 1, "benchmark": "live-re-skill", "manifestPresent": isinstance(manifest, dict), "trials": reports,
              "comparison": compare(reports), "assumptions": [
                  "Durations use integer monotonic nanoseconds. UTC is informational and is not used for subtraction.",
                  "Task starts at dispatched and ends at finished; setup and prepared opens are reported separately and excluded from task speedups.",
                  "Workers are numeric actor strings starting at zero unless trial.workers explicitly lists actor identities.",
                  "The exact exclusive partition uses dispatch-to-first-read, research through final worker done, handoff to researchFinished, collection, merge, verification, and semantic review.",
                  "Research CLI overlap priority is artifacts, annotation, read. CLI wall is interval union; summed call time can exceed wall time. Both are reported.",
                  "Only recognized CLI categories are command spans; marker points are not commands. Failed spans still count. p95 uses nearest rank.",
                  "Fresh-open is separated within verification. Summary CLI spans are separated within verified-to-finished semantic review; the remainder is outside summary, not inferred model time.",
                  "Outside CLI includes orchestration, reasoning, file work, scheduling and unobserved time. No model inference duration is inferred.",
                  "Post-last-read and writing-marker durations may include overlapping CLI work; they are descriptive and are not additional exclusive partition buckets.",
                  "CPU growth is sampled process CPU within the recorded common window, independent of wall-time attribution. Recorded proof is retained even when samples are absent.",
                  "All expected trials and extra attempts are retained, including failures. Speedups require both paired trials passed, cleanupComplete, and complete consistent telemetry. Failed trials never count as faster results.",
                  "Three pairs provide descriptive median and range only, modest evidence without population or causal claims. No raw receipt paths, stderr, prompts, or prior answers are read into this report.",
              ]}
    rendered = json.dumps(portable(report), indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError):
        print(json.dumps({"schema": 1, "error": "analysis_failed"}))
        sys.exit(2)

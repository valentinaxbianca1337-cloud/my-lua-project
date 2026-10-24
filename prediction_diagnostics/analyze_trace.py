#!/usr/bin/env python3
"""Summarize an observed GameSense trace without guessing server time or aim corrections."""
from __future__ import annotations
import argparse
from collections import Counter
import json
import math
from pathlib import Path
from statistics import median
from typing import Any

FORMAT = 'skeet-prediction-diagnostics'
MAX_BYTES = 20 * 1024 * 1024

def finite(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value)

def integer(value: Any, minimum: int = 0) -> bool:
    return finite(value) and minimum <= value < 2**53 and value == math.floor(value)

def array(value: Any, name: str) -> list:
    if value == {}:  # Some Lua JSON encoders represent an empty array as {}.
        return []
    if not isinstance(value, list):
        raise ValueError(f'{name} must be an array')
    return value

def stats(values: list[float]) -> dict:
    if not values:
        return {'count': 0}
    values = sorted(values)
    return {'count': len(values), 'median': median(values),
            'p95': values[max(0, math.ceil(.95 * len(values)) - 1)], 'maximum': values[-1]}

def estimated_lerp(cvars: dict) -> float | None:
    """Convar-based estimate only; no inference about the native Rage query time."""
    rate, ratio, interp = (cvars.get(k) for k in ('cl_updaterate', 'cl_interp_ratio', 'cl_interp'))
    if not all(finite(x) for x in (rate, ratio, interp)) or rate <= 0 or ratio < 0 or interp < 0:
        return None
    lo, hi = cvars.get('sv_minupdaterate'), cvars.get('sv_maxupdaterate')
    if finite(lo) and finite(hi) and 0 < lo <= hi:
        rate = max(lo, min(rate, hi))
    ratio = ratio or 1
    lo, hi = cvars.get('sv_client_min_interp_ratio'), cvars.get('sv_client_max_interp_ratio')
    if finite(lo) and finite(hi) and 0 <= lo <= hi:
        ratio = max(lo, min(ratio, hi))
    return max(interp, ratio / rate)

def validate(document: Any) -> tuple[dict, list, list]:
    if not isinstance(document, dict) or document.get('format') != FORMAT or not integer(document.get('version'), 1) or document['version'] != 1:
        raise ValueError('Unsupported trace format/version')
    meta = document.get('metadata')
    if not isinstance(meta, dict):
        raise ValueError('metadata must be an object')
    samples, events = array(document.get('samples'), 'samples'), array(document.get('events'), 'events')
    for rows, label in ((samples, 'samples'), (events, 'events')):
        previous = 0
        for row in rows:
            if not isinstance(row, dict) or not integer(row.get('sequence'), 1) or row['sequence'] <= previous:
                raise ValueError(f'{label} sequence must be strictly increasing')
            previous = row['sequence']
    for sample in samples:
        if not integer(sample.get('entity'), 1) or sample['entity'] > 128 or not integer(sample.get('generation')):
            raise ValueError('Invalid sample entity/generation')
        if type(sample.get('active')) is not bool:
            raise ValueError('Sample active must be boolean')
        if not finite(sample.get('receive_time')):
            raise ValueError('Sample receive_time must be finite')
        if sample['active']:
            if not finite(sample.get('simulation_time')) or not finite(sample.get('tick_interval')) or not 1e-6 <= sample['tick_interval'] <= 1:
                raise ValueError('Active sample needs finite simulation time and a positive tick interval')
            for key in ('origin', 'velocity'):
                vector = sample.get(key)
                if not isinstance(vector, list) or len(vector) != 3 or not all(finite(x) for x in vector):
                    raise ValueError(f'Sample {key} must be a finite 3-vector')
    for event in events:
        if not isinstance(event.get('kind'), str):
            raise ValueError('Event kind must be a string')
        if event['kind'].startswith('aim_') and not isinstance(event.get('native'), dict):
            raise ValueError('Aim event native must be an object')
    return meta, samples, events

def summarize(document: Any) -> dict:
    meta, samples, events = validate(document)
    active = [row for row in samples if row['active']]
    latency_ms = [row['reported_latency'] * 1000 for row in active
                  if finite(row.get('reported_latency')) and row['reported_latency'] >= 0]
    latency_ticks = [row['reported_latency'] / row['tick_interval'] for row in active
                     if finite(row.get('reported_latency')) and row['reported_latency'] >= 0]
    advances, receive_gaps, clock_regressions = [], [], 0
    duplicate_times, simulation_regressions = 0, 0
    previous = {}
    for row in samples:
        key = (row['entity'], row['generation'])
        old = previous.get(key)
        if not row['active']:
            previous.pop(key, None)
            continue
        if old and row['tick_interval'] == old['tick_interval']:
            delta = row['simulation_time'] - old['simulation_time']
            receive_delta = row['receive_time'] - old['receive_time']
            if receive_delta < 0:
                clock_regressions += 1
            else:
                receive_gaps.append(receive_delta * 1000)
            if delta > 1e-6:
                advances.append(delta / row['tick_interval'])
            elif delta < -1e-6:
                simulation_regressions += 1
            else:
                duplicate_times += 1
        previous[key] = row
    fires = {row['sequence']: row for row in events if row['kind'] == 'aim_fire'}
    flag_counts = {}
    for flag in ('interpolated', 'extrapolated', 'teleported', 'boosted', 'high_priority'):
        flag_counts[flag] = dict(Counter('true' if row['native'].get(flag) is True else
                                        'false' if row['native'].get(flag) is False else 'unreported'
                                        for row in fires.values()))
    reasons, matched, unmatched, duplicate_outcomes, completed = Counter(), Counter(), 0, 0, set()
    for event in events:
        if event['kind'] not in ('aim_hit', 'aim_miss'):
            continue
        if event['kind'] == 'aim_miss':
            reason = event['native'].get('reason')
            reasons[reason if isinstance(reason, str) else '(unreported)'] += 1
        fire = fires.get(event.get('fire_sequence'))
        if not fire or fire['native'].get('id') != event['native'].get('id'):
            unmatched += 1
        elif event['fire_sequence'] in completed:
            duplicate_outcomes += 1
        else:
            matched[event['kind']] += 1
            completed.add(event['fire_sequence'])
    lerps = []
    for value in [meta.get('cvars', {})] + [row.get('cvars', {}) for row in fires.values()]:
        if isinstance(value, dict):
            result = estimated_lerp(value)
            if result is not None:
                lerps.append(result * 1000)
    ages = [event['sample_receive_age'] * 1000 for event in fires.values()
            if finite(event.get('sample_receive_age')) and event['sample_receive_age'] >= 0]
    notes = [
        'Public Lua event flags describe native observations; they do not prove the new predictor is integrated.',
        'Reported latency is kept in its host API meaning; it is not automatically added to prediction time.',
        'Simulation advance may reflect batching/choke/loss or update cadence; this trace alone cannot distinguish them.',
        'Convar-based lerp is an estimate, not the Rage-selected record time.',
        'Miss reasons are reported by the host; they are not an independently verified diagnosis.',
    ]
    if not fires:
        notes.append('No aim_fire events were captured. Reproduce the issue with recording enabled.')
    if not active:
        notes.append('No active enemy samples were captured.')
    if meta.get('samples_dropped', 0) or meta.get('events_dropped', 0):
        notes.append('The bounded rolling window discarded older entries; unmatched outcomes may refer to discarded fires.')
    return {
        'format': 'skeet-prediction-diagnostics-summary', 'version': 1,
        'active_samples': len(active), 'entities_and_generations': len({(r['entity'],r['generation']) for r in samples}),
        'tick_rates': sorted({round(1 / row['tick_interval'], 3) for row in active}),
        'reported_latency_ms': stats(latency_ms), 'reported_latency_in_ticks': stats(latency_ticks),
        'simulation_advance_ticks': stats(advances),
        'advances_over_one_tick': sum(delta > 1.5 for delta in advances),
        'receive_gap_ms': stats(receive_gaps), 'changed_duplicate_simulation_times': duplicate_times,
        'simulation_time_regressions': simulation_regressions, 'receive_clock_regressions': clock_regressions,
        'aim_fire_events': len(fires), 'native_flags': flag_counts,
        'matched_outcomes': dict(matched), 'unmatched_outcomes': unmatched, 'duplicate_outcomes': duplicate_outcomes,
        'reported_miss_reasons': dict(reasons), 'sample_receive_age_at_fire_ms': stats(ages),
        'estimated_lerp_from_cvars_ms': stats(lerps), 'capture_metadata': meta,
        'prediction_improvement_measured': False, 'notes': notes,
    }

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        if args.trace.stat().st_size > MAX_BYTES:
            raise ValueError('Trace exceeds 20 MiB')
        def reject_constant(value: str) -> None:
            raise ValueError('Non-finite JSON value: ' + value)
        document = json.loads(args.trace.read_text(encoding='utf-8-sig'), parse_constant=reject_constant)
        result = summarize(document)
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    rendered = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + '\n'
    if args.output:
        args.output.write_text(rendered, encoding='utf-8')
    print(rendered, end='')
if __name__ == '__main__':
    main()

import json
import os
import datetime
from zoneinfo import ZoneInfo

import boto3
from boto3.dynamodb.conditions import Key

TABLE_NAME = os.environ["TABLE_NAME"]
TIMEZONE = os.environ.get("TIMEZONE", "America/Los_Angeles")

ddb = boto3.resource("dynamodb")
table = ddb.Table(TABLE_NAME)

def _now_utc():
    return datetime.datetime.now(datetime.timezone.utc)

def _day_string(dt_utc: datetime.datetime) -> str:
    tz = ZoneInfo(TIMEZONE)
    local = dt_utc.astimezone(tz)
    return local.strftime("%Y-%m-%d")

def _pk(day: str) -> str:
    return f"DAY#{day}"

def _session_sk(session_id: str) -> str:
    return f"SESSION#{session_id}"

def _event_sk(session_id: str, iso: str) -> str:
    return f"SESSION#{session_id}#EVENT#{iso}"

def _parse_iso(iso: str):
    if not iso:
        return None
    try:
        return datetime.datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except Exception:
        return None

def ensure_session_header(day: str, session_id: str, now_iso: str):
    table.update_item(
        Key={"pk": _pk(day), "sk": _session_sk(session_id)},
        UpdateExpression="SET firstSeenIso = if_not_exists(firstSeenIso, :now), #d = if_not_exists(#d, :day)",
        ExpressionAttributeNames={"#d": "day"},
        ExpressionAttributeValues={":now": now_iso, ":day": day},
    )

def compute_session(day: str, session_id: str):
    header = table.get_item(Key={"pk": _pk(day), "sk": _session_sk(session_id)}).get("Item", {})
    first_seen_iso = header.get("firstSeenIso", "")
    reasons_csv = header.get("reasonsCsv", "")

    resp = table.query(
        KeyConditionExpression=Key("pk").eq(_pk(day)) & Key("sk").begins_with(f"SESSION#{session_id}#EVENT#"),
        ScanIndexForward=True,
    )

    items = resp.get("Items", [])
    events = sorted(
        [{"timestampIso": it.get("timestampIso", ""), "station": it.get("station", "")} for it in items],
        key=lambda x: x.get("timestampIso", ""),
    )

    entry_iso = events[0]["timestampIso"] if events else first_seen_iso
    total_wait_seconds = 0
    if entry_iso:
        entry_dt = _parse_iso(entry_iso)
        if entry_dt:
            total_wait_seconds = max(0, int((_now_utc() - entry_dt).total_seconds()))

    return {
        "ok": True,
        "day": day,
        "timezone": TIMEZONE,
        "sessionId": session_id,
        "entryIso": entry_iso or "",
        "totalWaitSeconds": total_wait_seconds,
        "reasonsCsv": reasons_csv,
        "events": events,
    }

def respond(payload: dict, status_code: int = 200):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(payload),
    }

def _get_body(event):
    if isinstance(event, dict) and event.get("body"):
        try:
            return json.loads(event["body"])
        except Exception:
            return {}
    return (event or {}).get("payload") or {}

def _route_name(event):
    raw_path = (event or {}).get("rawPath") or "/"
    if raw_path.startswith("/api/"):
        return raw_path[len("/api/"):]
    return (event or {}).get("route") or ""

def admin_day(day: str):
    resp = table.query(
        KeyConditionExpression=Key("pk").eq(_pk(day)),
        ScanIndexForward=True,
    )
    items = resp.get("Items", [])

    sessions = {}
    for it in items:
        sid = it.get("sessionId")
        if not sid:
            sk = it.get("sk", "")
            if sk.startswith("SESSION#") and "#EVENT#" in sk:
                sid = sk.split("#", 2)[1]
        if not sid:
            continue

        sessions.setdefault(sid, {"sessionId": sid, "events": [], "reasonsCsv": "", "firstSeenIso": ""})

        if it.get("type") == "event" or "#EVENT#" in it.get("sk", ""):
            sessions[sid]["events"].append({"timestampIso": it.get("timestampIso",""), "station": it.get("station","")})
        else:
            sessions[sid]["reasonsCsv"] = it.get("reasonsCsv","") or sessions[sid]["reasonsCsv"]
            sessions[sid]["firstSeenIso"] = it.get("firstSeenIso","") or sessions[sid]["firstSeenIso"]

    def _percentile(sorted_secs, p):
        if not sorted_secs:
            return 0
        k = (len(sorted_secs) - 1) * (p / 100.0)
        f = int(k)
        c = min(f + 1, len(sorted_secs) - 1)
        if f == c:
            return int(sorted_secs[f])
        d0 = sorted_secs[f] * (c - k)
        d1 = sorted_secs[c] * (k - f)
        return int(d0 + d1)

    out_sessions = []
    total_secs = 0

    transitions = {}  # (from,to) -> [secs...]
    arrivals_counts = [0] * 24  # local hour bins in TIMEZONE
    tz = ZoneInfo(TIMEZONE)

    for sid, s in sessions.items():
        ev = sorted(s["events"], key=lambda x: x.get("timestampIso",""))
        entry_iso = ev[0]["timestampIso"] if ev else (s.get("firstSeenIso","") or "")
        last_iso = ev[-1]["timestampIso"] if ev else entry_iso

        entry_dt = _parse_iso(entry_iso) if entry_iso else None
        last_dt = _parse_iso(last_iso) if last_iso else None

        duration = 0
        if entry_dt and last_dt:
            duration = max(0, int((last_dt - entry_dt).total_seconds()))
        total_secs += duration

        # arrivals histogram (use earliest timestamp)
        if entry_dt:
            local = entry_dt.astimezone(tz)
            h = int(local.hour)
            if 0 <= h <= 23:
                arrivals_counts[h] += 1

        # transitions
        for i in range(len(ev) - 1):
            a = ev[i]
            b = ev[i+1]
            a_dt = _parse_iso(a.get("timestampIso",""))
            b_dt = _parse_iso(b.get("timestampIso",""))
            frm = (a.get("station","") or "").strip()
            to = (b.get("station","") or "").strip()
            if not a_dt or not b_dt or not frm or not to:
                continue
            secs = max(0, int((b_dt - a_dt).total_seconds()))
            transitions.setdefault((frm, to), []).append(secs)

        stations = [e.get("station","") for e in ev if e.get("station","")]

        out_sessions.append({
            "sessionId": sid,
            "entryIso": entry_iso,
            "lastIso": last_iso,
            "durationSeconds": duration,
            "reasonsCsv": s.get("reasonsCsv",""),
            "stations": stations,
            "events": ev  # needed for wide CSV export
        })

    out_sessions.sort(key=lambda x: x.get("entryIso",""))
    avg = int(total_secs / len(out_sessions)) if out_sessions else 0

    transition_rows = []
    for (frm, to), durs in transitions.items():
        durs_sorted = sorted(durs)
        transition_rows.append({
            "from": frm,
            "to": to,
            "count": len(durs_sorted),
            "avgSeconds": int(sum(durs_sorted) / len(durs_sorted)),
            "p50Seconds": _percentile(durs_sorted, 50),
            "p90Seconds": _percentile(durs_sorted, 90),
        })
    transition_rows.sort(key=lambda x: x["avgSeconds"], reverse=True)

    arrivals = [{"hour": h, "count": arrivals_counts[h]} for h in range(24)]

    return {
        "ok": True,
        "day": day,
        "timezone": TIMEZONE,
        "countSessions": len(out_sessions),
        "avgDurationSeconds": avg,
        "sessions": out_sessions,
        "transitions": transition_rows,
        "arrivalsByHour": arrivals
    }

def handler(event, context):
    is_http_api = isinstance(event, dict) and ("rawPath" in event)
    route = _route_name(event)
    body = _get_body(event)

    try:
        if route == "logEvent":
            session_id = str(body.get("sessionId", "")).strip()
            station = str(body.get("station", "")).strip()
            if not session_id or not station:
                out = {"ok": False, "error": "Missing sessionId or station"}
                return respond(out, 400) if is_http_api else out

            now = _now_utc()
            now_iso = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
            day = _day_string(now)

            table.put_item(
                Item={
                    "pk": _pk(day),
                    "sk": _event_sk(session_id, now_iso),
                    "type": "event",
                    "day": day,
                    "sessionId": session_id,
                    "station": station,
                    "timestampIso": now_iso,
                    "clientTimestampIso": str(body.get("clientTimestampIso", "") or ""),
                    "userAgent": str(body.get("userAgent", "") or ""),
                }
            )

            ensure_session_header(day, session_id, now_iso)
            out = compute_session(day, session_id)
            return respond(out, 200) if is_http_api else out

        if route == "saveReasons":
            session_id = str(body.get("sessionId", "")).strip()
            reasons = body.get("reasons") if isinstance(body.get("reasons"), list) else []
            reasons_csv = ",".join([str(r).strip() for r in reasons if str(r).strip()])

            day = _day_string(_now_utc())

            table.update_item(
                Key={"pk": _pk(day), "sk": _session_sk(session_id)},
                UpdateExpression="SET reasonsCsv = :r",
                ExpressionAttributeValues={":r": reasons_csv},
            )
            out = {"ok": True}
            return respond(out, 200) if is_http_api else out

        if route == "getSession":
            session_id = str(body.get("sessionId", "")).strip()
            day = str(body.get("day") or _day_string(_now_utc()))
            out = compute_session(day, session_id)
            return respond(out, 200) if is_http_api else out

        if route == "adminDay":
            day = str(body.get("day") or _day_string(_now_utc()))
            out = admin_day(day)
            return respond(out, 200) if is_http_api else out

        out = {"ok": False, "error": "Unknown route"}
        return respond(out, 404) if is_http_api else out

    except Exception as e:
        out = {"ok": False, "error": str(e)}
        return respond(out, 500) if is_http_api else out
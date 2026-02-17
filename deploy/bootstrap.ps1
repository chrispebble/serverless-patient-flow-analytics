$bootstrap = @"
param(
  [string]`$App = "qr-timetracker",
  [string]`$Stage = "prod",
  [string]`$Region = "us-east-1",
  [string]`$Timezone = "America/Los_Angeles"
)

Set-StrictMode -Version Latest
`$ErrorActionPreference = "Stop"

function Write-Section(`$t){ Write-Host ""; Write-Host ("==== " + `$t + " ====") -ForegroundColor Cyan }

# Requirements: aws, zip support (Compress-Archive), jq not required
Write-Section "Config"
`$AccountId = (aws sts get-caller-identity --query Account --output text)
`$Rand = (Get-Random -Minimum 100000 -Maximum 999999)
`$SiteBucket = "`$App-`$Stage-site-`$AccountId-`$Rand"
`$TableName = "`$App-`$Stage-events"
`$LambdaName = "`$App-`$Stage-api"
`$RoleName = "`$App-`$Stage-lambda-role"
`$PolicyName = "`$App-`$Stage-lambda-ddb"
`$FnName = "`$App-`$Stage-rewrite-station"

Write-Host "AccountId:  `$AccountId"
Write-Host "Region:     `$Region"
Write-Host "Bucket:     `$SiteBucket"
Write-Host "Table:      `$TableName"
Write-Host "Lambda:     `$LambdaName"
Write-Host "Timezone:   `$Timezone"

Write-Section "Create DynamoDB table (if needed)"
`$existing = aws dynamodb list-tables --region `$Region --query "TableNames[?@=='`$TableName']" --output text
if(-not `$existing){
  aws dynamodb create-table --region `$Region `
    --table-name `$TableName `
    --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S `
    --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE `
    --billing-mode PAY_PER_REQUEST | Out-Null

  aws dynamodb wait table-exists --region `$Region --table-name `$TableName
  Write-Host "Created table: `$TableName"
}else{
  Write-Host "Table exists: `$TableName"
}

Write-Section "Create IAM role for Lambda (if needed)"
`$roleArn = ""
try {
  `$roleArn = (aws iam get-role --role-name `$RoleName --query Role.Arn --output text 2>`$null)
} catch { }

if(-not `$roleArn){
  `$trust = @"
{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Effect":"Allow",
      "Principal":{"Service":"lambda.amazonaws.com"},
      "Action":"sts:AssumeRole"
    }
  ]
}
"@
  [System.IO.File]::WriteAllText("deploy-trust.json", `$trust, (New-Object System.Text.UTF8Encoding(`$false)))

  aws iam create-role --role-name `$RoleName --assume-role-policy-document file://deploy-trust.json | Out-Null
  `$roleArn = (aws iam get-role --role-name `$RoleName --query Role.Arn --output text)
  aws iam attach-role-policy --role-name `$RoleName --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole | Out-Null
  Write-Host "Created role: `$RoleName"
}else{
  Write-Host "Role exists: `$RoleName"
}

Write-Section "Create/Update DynamoDB access policy"
`$policyArn = ""
try { `$policyArn = (aws iam list-policies --scope Local --query "Policies[?PolicyName=='`$PolicyName'].Arn|[0]" --output text) } catch { }

`$ddbPolicy = @"
{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Effect":"Allow",
      "Action":[
        "dynamodb:PutItem",
        "dynamodb:GetItem",
        "dynamodb:UpdateItem",
        "dynamodb:Query"
      ],
      "Resource":[
        "arn:aws:dynamodb:`$Region:`$AccountId:table/`$TableName"
      ]
    }
  ]
}
"@
[System.IO.File]::WriteAllText("deploy-ddb-policy.json", `$ddbPolicy, (New-Object System.Text.UTF8Encoding(`$false)))

if(-not `$policyArn -or `$policyArn -eq "None"){
  aws iam create-policy --policy-name `$PolicyName --policy-document file://deploy-ddb-policy.json | Out-Null
  `$policyArn = (aws iam list-policies --scope Local --query "Policies[?PolicyName=='`$PolicyName'].Arn|[0]" --output text)
  aws iam attach-role-policy --role-name `$RoleName --policy-arn `$policyArn | Out-Null
  Write-Host "Created policy: `$PolicyName"
}else{
  aws iam create-policy-version --policy-arn `$policyArn --policy-document file://deploy-ddb-policy.json --set-as-default | Out-Null
  Write-Host "Updated policy: `$PolicyName"
  try { aws iam attach-role-policy --role-name `$RoleName --policy-arn `$policyArn | Out-Null } catch { }
}

Write-Section "Write Lambda code (Python)"
New-Item -ItemType Directory -Force -Path lambda | Out-Null

`$lambdaPy = @"
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

def respond(payload: dict, status_code: int = 200):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "Access-Control-Allow-Origin": "*"
        },
        "body": json.dumps(payload),
    }

def _get_body(event):
    if isinstance(event, dict) and event.get("body"):
        try:
            return json.loads(event["body"])
        except Exception:
            return {}
    return {}

def _route_name(event):
    raw_path = (event or {}).get("rawPath") or "/"
    if raw_path.startswith("/api/"):
        return raw_path[len("/api/"):]
    return ""

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

def admin_day(day: str):
    resp = table.query(
        KeyConditionExpression=Key("pk").eq(_pk(day)),
        ScanIndexForward=True,
    )
    items = resp.get("Items", [])

    sessions = {}
    for it in items:
        sid = it.get("sessionId")
        sk = it.get("sk","")
        if not sid and sk.startswith("SESSION#") and "#EVENT#" in sk:
            sid = sk.split("#", 2)[1]
        if not sid:
            continue
        sessions.setdefault(sid, {"sessionId": sid, "events": [], "reasonsCsv": "", "firstSeenIso": ""})

        if it.get("type") == "event" or "#EVENT#" in sk:
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
    transitions = {}
    arrivals_counts = [0] * 24
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

        if entry_dt:
            local = entry_dt.astimezone(tz)
            h = int(local.hour)
            if 0 <= h <= 23:
                arrivals_counts[h] += 1

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
            "events": ev
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
    route = _route_name(event)
    body = _get_body(event)

    try:
        if route == "logEvent":
            session_id = str(body.get("sessionId","")).strip()
            station = str(body.get("station","")).strip()
            if not session_id or not station:
                return respond({"ok": False, "error": "Missing sessionId or station"}, 400)

            now = _now_utc()
            now_iso = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
            day = _day_string(now)

            table.put_item(Item={
                "pk": _pk(day),
                "sk": _event_sk(session_id, now_iso),
                "type": "event",
                "day": day,
                "sessionId": session_id,
                "station": station,
                "timestampIso": now_iso,
                "clientTimestampIso": str(body.get("clientTimestampIso","") or ""),
                "userAgent": str(body.get("userAgent","") or "")
            })
            ensure_session_header(day, session_id, now_iso)
            return respond(compute_session(day, session_id), 200)

        if route == "saveReasons":
            session_id = str(body.get("sessionId","")).strip()
            reasons = body.get("reasons") if isinstance(body.get("reasons"), list) else []
            reasons_csv = ",".join([str(r).strip() for r in reasons if str(r).strip()])
            day = _day_string(_now_utc())
            table.update_item(
                Key={"pk": _pk(day), "sk": _session_sk(session_id)},
                UpdateExpression="SET reasonsCsv = :r",
                ExpressionAttributeValues={":r": reasons_csv},
            )
            return respond({"ok": True}, 200)

        if route == "getSession":
            session_id = str(body.get("sessionId","")).strip()
            day = str(body.get("day") or _day_string(_now_utc()))
            return respond(compute_session(day, session_id), 200)

        if route == "adminDay":
            day = str(body.get("day") or _day_string(_now_utc()))
            return respond(admin_day(day), 200)

        return respond({"ok": False, "error": "Unknown route"}, 404)
    except Exception as e:
        return respond({"ok": False, "error": str(e)}, 500)
"@

[System.IO.File]::WriteAllText("lambda/lambda_function.py", `$lambdaPy, (New-Object System.Text.UTF8Encoding(`$false)))

if(Test-Path ".\lambda.zip"){ Remove-Item ".\lambda.zip" -Force }
Compress-Archive -Path ".\lambda\lambda_function.py" -DestinationPath ".\lambda.zip" -Force

Write-Section "Create/Update Lambda"
`$lambdaArn = ""
try { `$lambdaArn = (aws lambda get-function --region `$Region --function-name `$LambdaName --query Configuration.FunctionArn --output text 2>`$null) } catch { }

if(-not `$lambdaArn -or `$lambdaArn -eq "None"){
  aws lambda create-function --region `$Region `
    --function-name `$LambdaName `
    --runtime python3.13 `
    --handler lambda_function.handler `
    --role `$roleArn `
    --zip-file fileb://lambda.zip `
    --environment Variables="{TABLE_NAME=`"`$TableName`",TIMEZONE=`"`$Timezone`"}" | Out-Null
  `$lambdaArn = (aws lambda get-function --region `$Region --function-name `$LambdaName --query Configuration.FunctionArn --output text)
  Write-Host "Created Lambda: `$LambdaName"
}else{
  aws lambda update-function-code --region `$Region --function-name `$LambdaName --zip-file fileb://lambda.zip | Out-Null
  aws lambda update-function-configuration --region `$Region --function-name `$LambdaName --environment Variables="{TABLE_NAME=`"`$TableName`",TIMEZONE=`"`$Timezone`"}" | Out-Null
  Write-Host "Updated Lambda: `$LambdaName"
}

Write-Section "Create HTTP API (API Gateway v2)"
`$apiId = ""
try { `$apiId = (aws apigatewayv2 get-apis --region `$Region --query "Items[?Name=='`$App-`$Stage-httpapi'].ApiId|[0]" --output text) } catch { }
if(-not `$apiId -or `$apiId -eq "None"){
  `$apiId = (aws apigatewayv2 create-api --region `$Region --name "`$App-`$Stage-httpapi" --protocol-type HTTP --query ApiId --output text)
  Write-Host "Created API: `$apiId"
}else{
  Write-Host "API exists: `$apiId"
}

`$apiEndpoint = (aws apigatewayv2 get-api --region `$Region --api-id `$apiId --query ApiEndpoint --output text)

Write-Section "Create integration + routes"
`$integId = (aws apigatewayv2 get-integrations --region `$Region --api-id `$apiId --query "Items[0].IntegrationId" --output text 2>`$null)
if(-not `$integId -or `$integId -eq "None"){
  `$integId = (aws apigatewayv2 create-integration --region `$Region --api-id `$apiId `
    --integration-type AWS_PROXY --integration-uri `$lambdaArn --payload-format-version "2.0" `
    --query IntegrationId --output text)
  Write-Host "Created integration: `$integId"
}

`$routes = @("POST /api/logEvent","POST /api/saveReasons","POST /api/getSession","POST /api/adminDay")
foreach(`$rk in `$routes){
  `$exists = (aws apigatewayv2 get-routes --region `$Region --api-id `$apiId --query "Items[?RouteKey=='`$rk'].RouteId|[0]" --output text 2>`$null)
  if(-not `$exists -or `$exists -eq "None"){
    aws apigatewayv2 create-route --region `$Region --api-id `$apiId --route-key `$rk --target "integrations/`$integId" | Out-Null
    Write-Host "Created route: `$rk"
  }
}

Write-Section "Grant API Gateway permission to invoke Lambda"
try {
  aws lambda add-permission --region `$Region `
    --function-name `$LambdaName `
    --statement-id "`$App-`$Stage-apigw" `
    --action lambda:InvokeFunction `
    --principal apigateway.amazonaws.com `
    --source-arn "arn:aws:execute-api:`$Region:`$AccountId:`$apiId/*/*/*" | Out-Null
} catch {
  Write-Host "Permission already exists (or not needed)."
}

Write-Section "Create default stage"
try {
  aws apigatewayv2 create-stage --region `$Region --api-id `$apiId --stage-name '`$default' --auto-deploy | Out-Null
} catch {
  # exists
}
# ensure auto deploy
aws apigatewayv2 update-stage --region `$Region --api-id `$apiId --stage-name '`$default' --auto-deploy | Out-Null

Write-Section "Create S3 bucket + upload site"
aws s3api create-bucket --region `$Region --bucket `$SiteBucket | Out-Null

aws s3 sync ".\site" "s3://`$SiteBucket/" --region `$Region | Out-Null

Write-Section "Create CloudFront Function (rewrite /s/*)"
`$cfFn = @"
function handler(event) {
  var request = event.request;
  var uri = request.uri;

  if (uri.startsWith('/s/')) {
    var station = uri.slice(3);
    request.uri = '/index.html';
    request.querystring = request.querystring || {};
    request.querystring.station = { value: decodeURIComponent(station) };
    return request;
  }
  return request;
}
"@
[System.IO.File]::WriteAllText("cf-fn.js", `$cfFn, (New-Object System.Text.UTF8Encoding(`$false)))

`$fnCfg = @"
{
  "Comment": "Rewrite /s/* to /index.html?station=...",
  "Runtime": "cloudfront-js-2.0"
}
"@
[System.IO.File]::WriteAllText("function-config.json", `$fnCfg, (New-Object System.Text.UTF8Encoding(`$false)))

`$createFnOut = aws cloudfront create-function --name `$FnName --function-config file://function-config.json --function-code fileb://cf-fn.js 2>`$null
if(`$LASTEXITCODE -ne 0){
  Write-Host "CloudFront Function exists, updating..."
  `$desc = aws cloudfront describe-function --name `$FnName | ConvertFrom-Json
  `$etag = `$desc.ETag
  aws cloudfront update-function --name `$FnName --if-match `$etag --function-config file://function-config.json --function-code fileb://cf-fn.js | Out-Null
}
`$desc2 = aws cloudfront describe-function --name `$FnName | ConvertFrom-Json
`$etag2 = `$desc2.ETag
aws cloudfront publish-function --name `$FnName --if-match `$etag2 | Out-Null
`$fnArn = (aws cloudfront describe-function --name `$FnName --query FunctionSummary.FunctionMetadata.FunctionARN --output text)

Write-Section "Create CloudFront distribution"
# Make origin access control (OAC)
`$oacName = "`$App-`$Stage-oac"
`$oacId = (aws cloudfront list-origin-access-controls --query "OriginAccessControlList.Items[?Name=='`$oacName'].Id|[0]" --output text 2>`$null)
if(-not `$oacId -or `$oacId -eq "None"){
  `$oacCfg = @"
{
  "Name": "`$oacName",
  "Description": "OAC for S3 origin",
  "SigningProtocol": "sigv4",
  "SigningBehavior": "always",
  "OriginAccessControlOriginType": "s3"
}
"@
  [System.IO.File]::WriteAllText("oac.json", `$oacCfg, (New-Object System.Text.UTF8Encoding(`$false)))
  `$oacId = (aws cloudfront create-origin-access-control --origin-access-control-config file://oac.json --query OriginAccessControl.Id --output text)
}

# CloudFront distribution config
`$distCfg = @"
{
  "CallerReference": "`$App-`$Stage-`$Rand",
  "Comment": "`$App-`$Stage",
  "Enabled": true,
  "HttpVersion": "http2",
  "IsIPV6Enabled": true,
  "DefaultRootObject": "index.html",
  "Origins": {
    "Quantity": 2,
    "Items": [
      {
        "Id": "S3Origin",
        "DomainName": "`$SiteBucket.s3.amazonaws.com",
        "OriginAccessControlId": "`$oacId",
        "S3OriginConfig": { "OriginAccessIdentity": "" }
      },
      {
        "Id": "ApiOrigin",
        "DomainName": "`$apiId.execute-api.`$Region.amazonaws.com",
        "CustomOriginConfig": {
          "HTTPPort": 80,
          "HTTPSPort": 443,
          "OriginProtocolPolicy": "https-only",
          "OriginSslProtocols": { "Quantity": 1, "Items": ["TLSv1.2"] }
        }
      }
    ]
  },
  "DefaultCacheBehavior": {
    "TargetOriginId": "S3Origin",
    "ViewerProtocolPolicy": "redirect-to-https",
    "AllowedMethods": { "Quantity": 2, "Items": ["GET","HEAD"], "CachedMethods": { "Quantity": 2, "Items": ["GET","HEAD"] } },
    "Compress": true,
    "MinTTL": 0,
    "DefaultTTL": 86400,
    "MaxTTL": 31536000,
    "FunctionAssociations": {
      "Quantity": 1,
      "Items": [
        { "EventType": "viewer-request", "FunctionARN": "`$fnArn" }
      ]
    },
    "ForwardedValues": { "QueryString": true, "Cookies": { "Forward": "none" } }
  },
  "CacheBehaviors": {
    "Quantity": 1,
    "Items": [
      {
        "PathPattern": "/api/*",
        "TargetOriginId": "ApiOrigin",
        "ViewerProtocolPolicy": "redirect-to-https",
        "AllowedMethods": { "Quantity": 7, "Items": ["GET","HEAD","OPTIONS","PUT","POST","PATCH","DELETE"],
          "CachedMethods": { "Quantity": 2, "Items": ["GET","HEAD"] } },
        "Compress": false,
        "MinTTL": 0,
        "DefaultTTL": 0,
        "MaxTTL": 0,
        "ForwardedValues": {
          "QueryString": false,
          "Cookies": { "Forward": "none" },
          "Headers": { "Quantity": 0 },
          "QueryStringCacheKeys": { "Quantity": 0 }
        }
      }
    ]
  }
}
"@
[System.IO.File]::WriteAllText("dist.json", `$distCfg, (New-Object System.Text.UTF8Encoding(`$false)))

`$distId = ""
try {
  `$distId = (aws cloudfront list-distributions --query "DistributionList.Items[?Comment=='`$App-`$Stage'].Id|[0]" --output text 2>`$null)
} catch { }

if(-not `$distId -or `$distId -eq "None"){
  `$create = aws cloudfront create-distribution --distribution-config file://dist.json | ConvertFrom-Json
  `$distId = `$create.Distribution.Id
  Write-Host "Created distribution: `$distId"
}else{
  Write-Host "Distribution exists: `$distId (manual update recommended for config changes)"
}

Write-Section "Attach bucket policy for OAC"
`$policy = @"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCloudFrontReadViaOAC",
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::`$SiteBucket/*",
      "Condition": {
        "StringEquals": {
          "AWS:SourceArn": "arn:aws:cloudfront::`$AccountId:distribution/`$distId"
        }
      }
    }
  ]
}
"@
[System.IO.File]::WriteAllText("bucket-policy.json", `$policy, (New-Object System.Text.UTF8Encoding(`$false)))
aws s3api put-bucket-policy --bucket `$SiteBucket --policy file://bucket-policy.json | Out-Null

Write-Section "Outputs"
`$domain = (aws cloudfront get-distribution --id `$distId --query "Distribution.DomainName" --output text)
Write-Host "CloudFront Domain: https://`$domain"
Write-Host "API Endpoint:      `$apiEndpoint"
Write-Host "S3 Bucket:         `$SiteBucket"
Write-Host "DynamoDB Table:    `$TableName"

Write-Host ""
Write-Host "Next:"
Write-Host " - Upload your real site files into .\site and run: aws s3 sync .\site s3://`$SiteBucket/ --delete"
Write-Host " - Invalidate: aws cloudfront create-invalidation --distribution-id `"`$distId`" --paths `"/*`""
"@

[System.IO.File]::WriteAllText("$PWD\deploy\bootstrap.ps1", $bootstrap, (New-Object System.Text.UTF8Encoding($false)))
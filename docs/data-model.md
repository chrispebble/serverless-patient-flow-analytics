# DynamoDB Data Model

## Keys
- pk: DAY#YYYY-MM-DD
- sk:
  - SESSION#<sessionId>                         (session header)
  - SESSION#<sessionId>#EVENT#<timestampIso>    (event record)

## Session header attributes
- day
- firstSeenIso
- reasonsCsv

## Event record attributes
- type = event
- sessionId
- station
- timestampIso
- clientTimestampIso (optional)
- userAgent (optional)

This structure supports:
- Daily query by partition key
- Ordered events by sort key lexicographic ISO time
- Fast analytics generation

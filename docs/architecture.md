# Architecture Notes

## Why serverless?
- Minimal operational overhead (no servers)
- Extremely low cost at < 200 patients/day
- Scales automatically

## Why CloudFront + S3?
- Static front-end is simplest and cheapest
- CloudFront Function enables clean station URLs:
  - /s/Entrance → /index.html?station=Entrance

## Why DynamoDB day-partitioning?
Daily reporting is the core access pattern:
- Query all items for a day from a single partition
- Reconstruct per-session sequences from sort keys
- Compute transitions and arrival histograms without table scans

## Caching strategy
- Static assets can be cached
- API responses should not be cached (Cache-Control: no-store)
- During development, use invalidations or disable caching for HTML paths

## Operational metrics
- Total duration: first scan to last scan
- Transition metrics: consecutive station deltas
- Arrival histogram: hour of day (local clinic timezone) of first scan

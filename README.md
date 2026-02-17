# Serverless Patient Flow Analytics

A production-ready, serverless operational analytics system that measures real-world patient flow using QR code scans.

Built on AWS (CloudFront, S3, Lambda, API Gateway, DynamoDB), this system provides objective metrics on where patients spend time inside a clinical workflow — without requiring a mobile app or user accounts.

---

## Overview

This project was designed to solve a practical operational problem:

> Clinics often lack objective data about patient movement and bottlenecks.  
> Most workflow decisions are based on anecdotal observation rather than measurable metrics.

This system enables:

- Tracking patient flow through defined stations  
- Measuring time spent between stations  
- Identifying workflow bottlenecks  
- Visualizing arrival patterns  
- Exporting structured data for leadership review  

All without collecting protected health information.

---

## How It Works

### Patient Flow

QR codes are posted at clinical stations:

- Entrance  
- Check-In  
- Admin  
- Vitals  
- IMR  
- Provider  
- Lab  
- Radiology  
- Immunizations  
- Check-Out  

When a patient scans a QR code:

1. A session is created (or resumed)  
2. A timestamped event is stored  
3. The system calculates total elapsed time  
4. The session is updated in DynamoDB  

Each visit becomes a structured sequence of timestamped station transitions.

---

## Admin Dashboard

The admin interface provides:

- Total sessions per day  
- Average visit duration  
- Per-hour arrival histogram  
- Station-to-station transition analytics (avg, p50, p90)  
- Wide-format CSV export  
  - One row per session  
  - One column per station  
  - Values = seconds since first scan  
- Reasons-for-visit field  
- QR generator with large poster mode  

---

## Architecture

### Static Frontend

- **S3** – static hosting  
- **CloudFront** – CDN + HTTPS  
- **CloudFront Function** – rewrites /s/<station> to /index.html?station=<station>  

### API Layer

- **API Gateway (HTTP API)** – routing  
- **Lambda (Python 3.13)** – event logging + analytics  

### Storage

- **DynamoDB** (partitioned by day)

Partition key strategy:

pk = DAY#YYYY-MM-DD  
sk = SESSION#<sessionId>  
sk = SESSION#<sessionId>#EVENT#<timestampIso>  

This design allows:

- Efficient daily queries  
- Sorted event reconstruction  
- Fast transition calculations  
- No table scans  

---

## Deployment (AWS)

The repository includes a one-shot bootstrap script:

deploy/bootstrap.ps1

This provisions the entire infrastructure stack:

- DynamoDB table (PAY_PER_REQUEST)  
- Lambda + IAM role  
- API Gateway + routes  
- S3 bucket for static site  
- CloudFront distribution  
- CloudFront Function rewrite logic  
- Bucket policy for Origin Access Control  

---

## Prerequisites

- Windows PowerShell  
- AWS CLI v2 configured (ws configure)  
- IAM permissions to create:
  - IAM roles/policies  
  - Lambda  
  - API Gateway  
  - DynamoDB  
  - S3  
  - CloudFront  

Verify AWS access:

aws sts get-caller-identity

---

## Run the Bootstrap

From the repository root:

.\deploy\bootstrap.ps1 
  -App "serverless-patient-flow-analytics" 
  -Stage "prod" 
  -Region "us-east-1" 
  -Timezone "America/Los_Angeles"

When the script completes, it outputs:

- CloudFront domain  
- API endpoint  
- S3 bucket name  
- DynamoDB table name  

---

## Updating the Site

After editing files in site/:

aws s3 sync .\site s3://<YOUR_SITE_BUCKET>/ --delete --region us-east-1

During development, invalidate CloudFront:

aws cloudfront create-invalidation --distribution-id <YOUR_CF_DISTRIBUTION_ID> --paths "/*"

---

## Accessing the Application

### Public scan URLs

https://<cloudfront-domain>/s/Entrance  
https://<cloudfront-domain>/s/Check-In  

### Admin dashboard

https://<cloudfront-domain>/admin.html  

### QR generator

https://<cloudfront-domain>/qr.html  

The QR generator supports a one-per-page poster mode with customizable title for printing station posters.

---

## Security and Privacy

- No PHI stored  
- Randomized session IDs  
- Minimal data retention footprint  
- Least-privilege IAM roles  
- API responses set to Cache-Control: no-store  

Admin authentication can be added if required.

---

## Cost Profile

At <200 patients per day:

- Lambda: negligible  
- DynamoDB: low single-digit dollars  
- API Gateway: low usage tier  
- CloudFront: minimal bandwidth  
- S3: negligible storage  

Typical monthly cost: approximately –10.

---

## Why Serverless?

This architecture was intentionally chosen for:

- Minimal operational overhead  
- High scalability  
- Low cost  
- Infrastructure-as-code deployment  
- Easy replication across environments  

---

## Professional Context

This project demonstrates:

- Real-world workflow analytics design  
- Event-driven system architecture  
- Serverless infrastructure provisioning  
- DynamoDB data modeling  
- CloudFront routing strategies  
- Operational metric computation  
- Practical application of technology to clinical operations  

It was built to solve an actual workflow measurement problem using modern cloud-native architecture.

---

## Future Enhancements

- Daily automated email summary (SES + EventBridge)  
- Admin authentication  
- Multi-site support  
- DynamoDB TTL retention policy  
- SLA breach alerts  
- Real-time dashboard view  

---

## License

MIT License
## Architecture Diagram

`mermaid
flowchart LR

  U[Patient / Staff Phone] --> CF[CloudFront CDN]

  CF --> CFF[CloudFront Function Rewrite]
  CFF --> CF

  CF -->|Static Assets| S3[S3 Static Site]

  CF -->|POST API| APIGW[API Gateway HTTP API]
  APIGW --> L[Lambda Python]

  L --> DDB[DynamoDB Day Partition]
  DDB --> L

  L --> APIGW
  APIGW --> CF
  CF --> U

  subgraph DataModel
    PK[pk = DAY-YYYY-MM-DD]
    SK1[sk = SESSION-sessionId]
    SK2[sk = SESSION-sessionId-EVENT-timestamp]
  end


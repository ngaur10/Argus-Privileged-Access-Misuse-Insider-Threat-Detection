
import json
import os
import boto3
import time
from datetime import datetime, timedelta, timezone
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource('dynamodb')
events_table = dynamodb.Table(os.environ.get('EVENTS_TABLE', 'PrivilegedEvents'))
incidents_table = dynamodb.Table(os.environ.get('INCIDENTS_TABLE', 'Incidents'))
sns = boto3.client('sns')
s3 = boto3.client('s3')
iam = boto3.client('iam')

# Configuration is injected via Lambda environment variables rather than
# hardcoded, so this function can be deployed to any account/region without
# code changes and without exposing account-specific identifiers in source.
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
EVIDENCE_BUCKET = os.environ['EVIDENCE_BUCKET']
DENY_POLICY_ARN = os.environ['DENY_POLICY_ARN']
PRIVILEGED_ROLE_NAME = os.environ.get('PRIVILEGED_ROLE_NAME', 'PrivilegedAdminRole')

# Weights modeling a banking privileged-access-misuse scenario.
EVENT_SCORES = {
    "AssumeRole": 20, "CreateAccessKey": 50,
    "PutUserPolicy": 40, "AttachUserPolicy": 40, "AttachRolePolicy": 40,
    "CreateUser": 20, "DeleteUser": 80, "DeleteRole": 90,
    "CreateLoginProfile": 20, "DeleteLoginProfile": 20, "CreatePolicyVersion": 60,
    "StopLogging": 95, "DeleteTrail": 95, "UpdateTrail": 40,
    "GuardDutyFinding": 70,
}


def score_event(event_type, request_params=None):
    if event_type in ("AttachUserPolicy", "AttachRolePolicy") and request_params:
        policy_arn = request_params.get("policyArn", "")
        if "AdministratorAccess" in policy_arn:
            return 95
        elif "PowerUserAccess" in policy_arn:
            return 70
        elif "IAMFullAccess" in policy_arn:
            return 70
        elif "ReadOnlyAccess" in policy_arn:
            return 10
        return 20
    return EVENT_SCORES.get(event_type, 10)


def classify_severity(total_score):
    if total_score >= 100:
        return "Critical"
    elif total_score >= 70:
        return "High"
    elif total_score >= 40:
        return "Medium"
    return "Low"


def get_recent_events(user_id, minutes=10):
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    resp = events_table.query(
        KeyConditionExpression=Key("userId").eq(user_id) & Key("timestamp").gt(cutoff)
    )
    return resp.get("Items", [])


def generate_explanation(user_id, event_list, total_score):
    event_names = [e["eventType"] for e in event_list]
    unique_events = ", ".join(sorted(set(event_names)))
    return (
        f"User '{user_id}' triggered {len(event_list)} scored event(s) "
        f"({unique_events}) within a 10-minute window, reaching a "
        f"cumulative risk score of {total_score}. This pattern matches "
        f"known privileged-access-misuse indicators such as privilege "
        f"escalation, credential creation, or audit-log tampering."
    )


def enforce_lockdown():
    try:
        iam.attach_role_policy(RoleName=PRIVILEGED_ROLE_NAME, PolicyArn=DENY_POLICY_ARN)
        return f"Attached emergency deny policy to {PRIVILEGED_ROLE_NAME}"
    except Exception as e:
        print(f"ERROR executing lockdown: {str(e)}")
        return f"Failed to attach lockdown policy: {str(e)}"


def lambda_handler(event, context):
    print("DEBUG 1 - RAW EVENT:")
    print(json.dumps(event))

    detail = event.get("detail", {})
    print("DEBUG 2 - DETAIL:")
    print(json.dumps(detail, default=str))

    request_params = detail.get("requestParameters", {}) or {}

    if event.get("source") == "aws.guardduty":
        resource = detail.get("resource", {})
        access = resource.get("accessKeyDetails", {})
        user_id = access.get("userName", "unknown-user")
        event_type = "GuardDutyFinding"
        event_id = detail.get("id", "n/a")
        source_ip = access.get("ipAddressV4", "n/a")
        event_source = "guardduty.amazonaws.com"
    else:
        identity = detail.get("userIdentity", {})
        if identity.get("type") == "AssumedRole":
            user_id = identity.get("sessionContext", {}) \
                               .get("sessionIssuer", {}) \
                               .get("userName")
            if not user_id:
                arn = identity.get("arn", "")
                parts = arn.split("/")
                user_id = parts[-2] if len(parts) >= 2 else "unknown-role"
        else:
            user_id = identity.get("userName", "unknown-user")

        event_type = detail.get("eventName", "UnknownEvent")
        event_id = detail.get("eventID", "unknown")
        source_ip = detail.get("sourceIPAddress", "unknown")
        event_source = detail.get("eventSource", "unknown")

    print("DEBUG 3 - EVENT TYPE:", event_type)
    print("DEBUG 3b - USER ID:", user_id)

    timestamp = datetime.now(timezone.utc).isoformat()
    score = score_event(event_type, request_params)
    print("DEBUG 4 - SCORE:", score)
    expire_at = int(time.time()) + 86400

    events_table.put_item(Item={
        "userId": user_id, "timestamp": timestamp,
        "eventType": event_type, "eventId": event_id,
        "eventSource": event_source, "sourceIp": source_ip,
        "policyArn": request_params.get("policyArn", ""),
        "score": int(score), "expireAt": expire_at
    })

    recent = get_recent_events(user_id)
    total_score = sum(int(e["score"]) for e in recent)
    severity = classify_severity(total_score)

    if severity == "Low":
        return {"status": "logged", "severity": severity}

    incident_id = f"{user_id}-{int(time.time())}"
    explanation = generate_explanation(user_id, recent, total_score)

    incident = {
        "incidentId": incident_id,
        "userId": user_id,
        "status": "OPEN",
        "eventType": event_type,
        "policyArn": request_params.get("policyArn", ""),
        "totalScore": total_score,
        "severity": severity,
        "automatedResponse": "None",
        "explanation": explanation,
        "events": recent,
        "timestamp": timestamp
    }

    if severity == "Critical":
        print(f"CRITICAL SEVERITY DETECTED ({total_score}). Triggering lockdown...")
        response_action = enforce_lockdown()
        incident["automatedResponse"] = response_action

    try:
        incidents_table.put_item(Item=incident)
        print(f"Incident {incident_id} successfully stored in DynamoDB.")
    except Exception as e:
        print(f"ERROR saving incident to DynamoDB: {str(e)}")

    try:
        evidence_key = f"incidents/{incident_id}/raw_event.json"
        s3.put_object(
            Bucket=EVIDENCE_BUCKET,
            Key=evidence_key,
            Body=json.dumps(event, indent=2, default=str),
            ContentType="application/json"
        )
        print(f"Raw evidence saved to S3: {evidence_key}")
    except Exception as e:
        print(f"ERROR saving evidence to S3: {str(e)}")

    try:
        sns_message = (
            f"\u26a0\ufe0f AWS PRIVILEGED ACCESS ALERT ({severity} Severity)\n\n"
            f"Incident ID: {incident_id}\n"
            f"Target User/Role: {user_id}\n"
            f"Triggering Event: {event_type}\n"
            f"Cumulative Risk Score: {total_score}\n"
            f"Mitigation Action Taken: {incident['automatedResponse']}\n\n"
            f"Explanation:\n{explanation}"
        )
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[{severity} Alert] Potential Access Misuse by {user_id}",
            Message=sns_message
        )
        print("SNS Alert broadcasted successfully.")
    except Exception as e:
        print(f"ERROR sending SNS: {str(e)}")

    return {"status": "incident_created", "incidentId": incident_id, "severity": severity}

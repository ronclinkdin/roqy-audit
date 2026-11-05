# roqy-lab harmless function. Reads nothing, writes nothing, never echoes env vars.
def handler(event, context):
    return {"statusCode": 200, "body": "roqy-lab hello (vulnerable-by-design sandbox)"}

# Python SDK for Phase

SDK to integrate Phase in server-side applications running Python. This SDK allows you to manage secrets securely using the Phase platform.

## Install

```
pip install phase-dev
```

## Import

```python
from phase import Secrets
```

## Initialize

Initialize the SDK with your host and token:

```python
phase = Secrets(
    host='https://your-phase-host.com', 
    pss=PHASE_SERVICE_TOKEN
)
```

## Usage

### Create Secrets

Create one or more secrets in a specified application and environment:

```python
new_secrets = [
    phase.PhaseSecret(
        key="API_KEY",
        value="your-api-key",
        comment="API key for our service",
        path="/",
        tags=["api", "credentials"],
        overridden=False
    ),
    # Add more secrets as needed
]

response = phase.create(secrets=new_secrets, env_name="Development", app_name="Your App Name")
print(f"Create Response Status Code: {response.status_code}")
```

### Get Secrets

Fetch one or more secrets from a specified application and environment:

```python
secrets = phase.get(
    env_name="Development", 
    keys=["API_KEY"],  # Optional: specify keys to retrieve
    app_name="Your App Name",
    tag="api",  # Optional: filter by tag
    path="/"  # Optional: specify path
)

for secret in secrets:
    print(f"Key: {secret.key}, Value: {secret.value}")
```

### Update Secrets

Update an existing secret in a specified application and environment:

```python
updated_secret = phase.PhaseSecret(
    key="API_KEY",
    value="new-api-key-value",
    comment="Updated API key",
    path="/",
    tags=["api", "credentials", "updated"],
    overridden=False
)

result = phase.update(
    secret=updated_secret, 
    env_name="Development", 
    app_name="Your App Name"
)
print(f"Update result: {result}")
```

### Delete Secrets

Delete one or more secrets from a specified application and environment:

```python
keys_to_delete = ["API_KEY", "DB_PASSWORD"]
result = phase.delete(
    env_name="Development",
    keys_to_delete=keys_to_delete,
    app_name="Your App Name",
    path="/"  # Optional: specify path
)

print(f"Deleted secrets: {result['deleted']}")
print(f"Secrets not found: {result['not_found']}")
```

## Error Handling

The SDK methods may raise exceptions for various error conditions. It's recommended to wrap SDK calls in try-except blocks to handle potential errors:

```python
try:
    secrets = phase.get(env_name="Development", app_name="Your App Name")
except ValueError as e:
    print(f"An error occurred: {e}")
```

## Note on Security

Never hard-code sensitive information like tokens or secrets directly in your code. Always use environment variables or secure configuration management to provide these values to your application.
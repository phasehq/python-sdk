# Python SDK for Phase

SDK to integrate Phase in server-side applications running Python. This SDK allows you to manage secrets securely using the Phase platform.

## Install

```
pip install phase-dev
```

## Import

```python
from phase import Phase, CreateSecretsOptions, GetAllSecretsOptions, GetSecretOptions, UpdateSecretOptions, DeleteSecretOptions
```

## Initialize

Initialize the SDK with your host and token:

```python
phase = Phase(
    init=False,
    host='https://your-phase-host.com',
    pss=PHASE_SERVICE_TOKEN

)
```

## Usage

### Create Secrets

Create one or more secrets in a specified application and environment:

```python
create_options = CreateSecretsOptions(
    env_name="Development",
    app_name="Your App Name",
    key_value_pairs=[
        {"API_KEY": "your-api-key"},
        {"DB_PASSWORD": "your-db-password"}
    ],
    secret_path="/api"
)
result = phase.create_secrets(create_options)
print(f"Create secrets result: {result}")
```

### Get Secrets

Fetch one or more secrets from a specified application and environment:

```python
get_options = GetAllSecretsOptions(
    env_name="Development",
    app_name="Your App Name",
    tag="api",  # Optional: filter by tag
    secret_path="/api"  # Optional: specify path
)
secrets = phase.get_all_secrets(get_options)
for secret in secrets:
    print(f"Key: {secret.key}, Value: {secret.value}")
```

To get a specific secret:

```python
get_options = GetSecretOptions(
    env_name="Development",
    app_name="Your App Name",
    key_to_find="API_KEY",
    secret_path="/api"
)
secret = phase.get_secret(get_options)
if secret:
    print(f"Key: {secret.key}, Value: {secret.value}")
```

### Update Secrets

Update an existing secret in a specified application and environment:

```python
update_options = UpdateSecretOptions(
    env_name="Development",
    app_name="Your App Name",
    key="API_KEY",
    value="new-api-key-value",
    secret_path="/api",
    destination_path="/new-api",  # Optional: move secret to a new path
    override=False,  # Optional: create a personal override
    toggle_override=False  # Optional: toggle personal override
)
result = phase.update_secret(update_options)
print(f"Update result: {result}")
```

### Delete Secrets

Delete a secret from a specified application and environment:

```python
delete_options = DeleteSecretOptions(
    env_name="Development",
    app_name="Your App Name",
    key_to_delete="API_KEY",
    secret_path="/api"
)
result = phase.delete_secret(delete_options)
print(f"Delete result: {result}")
```

### Resolve Secret References

Resolve references in secret values:

```python
get_options = GetAllSecretsOptions(
    env_name="Development",
    app_name="Your App Name"
)
secrets = phase.get_all_secrets(get_options)
resolved_secrets = phase.resolve_references(secrets, "Development", "Your App Name")
for secret in resolved_secrets:
    print(f"Key: {secret.key}, Resolved Value: {secret.value}")
```

## Error Handling

The SDK methods may raise exceptions for various error conditions. It's recommended to wrap SDK calls in try-except blocks to handle potential errors:

```python
try:
    get_options = GetAllSecretsOptions(env_name="Development", app_name="Your App Name")
    secrets = phase.get_all_secrets(get_options)
except ValueError as e:
    print(f"An error occurred: {e}")
```

## Note on Security

Never hard-code sensitive information like tokens or secrets directly in your code. Always use environment variables or secure configuration management to provide these values to your application.

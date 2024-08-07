## Local setup

Clone the reposistory to your machine and install the required dependencies.

### Create a virtual environment

```fish
python3 -m venv.venv
```

### Install dependencies

```fish
pip install -r requirements.txt
```

### Demo script

This demo python script will create, read, update and delete secrets via the SDK. Just update the host, app, env and token constants at the top.

```python
from src.phase import Phase, CreateSecretsOptions, GetAllSecretsOptions, UpdateSecretOptions, DeleteSecretOptions

CONSOLE_HOST = 'https://console.phase.dev'
APP_NAME = '<app-name>'
ENV_NAME = "<env-name>"
TOKEN = '<service-token>'

# Initialize the Phase object with host and service token
phase = Phase(init=False,
    pss=TOKEN,
    host=CONSOLE_HOST)

# Create secrets with references
create_options = CreateSecretsOptions(
    env_name=ENV_NAME,
    app_name=APP_NAME,
    key_value_pairs=[
        {"BASE_URL": "https://api.example.com"},
        {"API_ENDPOINT": "${BASE_URL}/v1/data"},
        {"NESTED_REF": "Nested ${API_ENDPOINT}"}
    ]
)
create_result = phase.create_secrets(create_options)
print(f"Create secrets result: {create_result}")

# Read and resolve references
get_options = GetAllSecretsOptions(
    env_name=ENV_NAME,
    app_name=APP_NAME
)
secrets = phase.get_all_secrets(get_options)

resolved_secrets = phase.resolve_references(secrets, ENV_NAME, APP_NAME)

print("\nResolved Secrets:")
print("----------------")
for secret in resolved_secrets:
    print(f"{secret.key}: {secret.value}")

# Update secrets
update_options = UpdateSecretOptions(
    env_name=ENV_NAME,
    app_name=APP_NAME,
    key="BASE_URL",
    value="https://api.acme.com",
    secret_path="/",
    destination_path="/",  # Optional: move secret to a new path
    override=False,  # Optional: create a personal override
    toggle_override=False  # Optional: toggle personal override
)
update_result = phase.update_secret(update_options)

print(f"\nUpdate secrets result: {update_result}")
print("----------------")


## Refetch secrets
secrets = phase.get_all_secrets(get_options)

resolved_secrets = phase.resolve_references(secrets, ENV_NAME, APP_NAME)

print("\nResolved Secrets:")
print("----------------")
for secret in resolved_secrets:
    print(f"{secret.key}: {secret.value}")


# Delete secrets
delete_options = DeleteSecretOptions(
    env_name=ENV_NAME,
    app_name=APP_NAME,
    key_to_delete="BASE_URL",
    secret_path="/"
)
result = phase.delete_secret(delete_options)
print(f"Delete result: {result}")

## Refetch secrets
secrets = phase.get_all_secrets(get_options)

resolved_secrets = phase.resolve_references(secrets, ENV_NAME, APP_NAME)

print("\nResolved Secrets:")
print("----------------")
for secret in resolved_secrets:
    print(f"{secret.key}: {secret.value}")
```

## Running Tests

Run the test suite with:

```fish
python -m pytest -v tests/
```

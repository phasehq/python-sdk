from dataclasses import dataclass, field
from typing import List, Dict, Optional
from .utils.phase_io import Phase as PhaseIO
from .utils.secret_referencing import resolve_all_secrets

@dataclass
class GetSecretOptions:
    env_name: str
    app_name: str
    key_to_find: Optional[str] = None
    tag: Optional[str] = None
    secret_path: str = "/"

@dataclass
class GetAllSecretsOptions:
    env_name: str
    app_name: str
    tag: Optional[str] = None
    secret_path: str = "/"

@dataclass
class CreateSecretsOptions:
    env_name: str
    app_name: str
    key_value_pairs: List[Dict[str, str]]
    secret_path: str = "/"

@dataclass
class UpdateSecretOptions:
    env_name: str
    app_name: str
    key: str
    value: Optional[str] = None
    secret_path: str = "/"
    destination_path: Optional[str] = None
    override: bool = False
    toggle_override: bool = False

@dataclass
class DeleteSecretOptions:
    env_name: str
    app_name: str
    key_to_delete: str
    secret_path: str = "/"

@dataclass
class PhaseSecret:
    key: str
    value: str
    comment: str = ""
    path: str = "/"
    tags: List[str] = field(default_factory=list)
    overridden: bool = False

class Phase:
    def __init__(self, init=True, pss=None, host=None):
        self._phase_io = PhaseIO(init=init, pss=pss, host=host)

    def get_secret(self, options: GetSecretOptions) -> Optional[PhaseSecret]:
        secrets = self._phase_io.get(
            env_name=options.env_name,
            keys=[options.key_to_find] if options.key_to_find else None,
            app_name=options.app_name,
            tag=options.tag,
            path=options.secret_path
        )
        if secrets:
            secret = secrets[0]
            return PhaseSecret(
                key=secret['key'],
                value=secret['value'],
                comment=secret.get('comment', ''),
                path=secret.get('path', '/'),
                tags=secret.get('tags', []),
                overridden=secret.get('overridden', False)
            )
        return None

    def get_all_secrets(self, options: GetAllSecretsOptions) -> List[PhaseSecret]:
        secrets = self._phase_io.get(
            env_name=options.env_name,
            app_name=options.app_name,
            tag=options.tag,
            path=options.secret_path
        )
        return [
            PhaseSecret(
                key=secret['key'],
                value=secret['value'],
                comment=secret.get('comment', ''),
                path=secret.get('path', '/'),
                tags=secret.get('tags', []),
                overridden=secret.get('overridden', False)
            )
            for secret in secrets
        ]

    def create_secrets(self, options: CreateSecretsOptions) -> str:
        # Convert the list of dictionaries to a list of tuples
        key_value_tuples = [(list(item.keys())[0], list(item.values())[0]) for item in options.key_value_pairs]
        
        response = self._phase_io.create(
            key_value_pairs=key_value_tuples,
            env_name=options.env_name,
            app_name=options.app_name,
            path=options.secret_path
        )
        return "Success" if response.status_code == 200 else f"Error: {response.status_code}"

    def update_secret(self, options: UpdateSecretOptions) -> str:
        return self._phase_io.update(
            env_name=options.env_name,
            key=options.key,
            value=options.value,
            app_name=options.app_name,
            source_path=options.secret_path,
            destination_path=options.destination_path,
            override=options.override,
            toggle_override=options.toggle_override
        )

    def delete_secret(self, options: DeleteSecretOptions) -> List[str]:
        return self._phase_io.delete(
            env_name=options.env_name,
            keys_to_delete=[options.key_to_delete],
            app_name=options.app_name,
            path=options.secret_path
        )

    def resolve_references(self, secrets: List[PhaseSecret], env_name: str, app_name: str) -> List[PhaseSecret]:
        all_secrets = [
            {
                'environment': env_name,
                'application': app_name,
                'key': secret.key,
                'value': secret.value,
                'path': secret.path
            }
            for secret in secrets
        ]
        
        for secret in secrets:
            resolved_value = resolve_all_secrets(
                secret.value, 
                all_secrets, 
                self._phase_io, 
                app_name, 
                env_name
            )
            secret.value = resolved_value
        
        return secrets
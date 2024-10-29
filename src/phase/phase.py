from dataclasses import dataclass, field
from typing import List, Dict, Optional
from .utils.phase_io import Phase as PhaseIO
from .utils.secret_referencing import resolve_all_secrets

@dataclass
class GetSecretOptions:
    env_name: str
    app_name: Optional[str] = None
    app_id: Optional[str] = None
    key_to_find: Optional[str] = None
    tag: Optional[str] = None
    secret_path: str = "/"

    def __post_init__(self):
        if not self.app_name and not self.app_id:
            raise ValueError("Either app_name or app_id must be provided")

@dataclass
class GetAllSecretsOptions:
    env_name: str
    app_name: Optional[str] = None
    app_id: Optional[str] = None
    tag: Optional[str] = None
    secret_path: str = "/"

    def __post_init__(self):
        if not self.app_name and not self.app_id:
            raise ValueError("Either app_name or app_id must be provided")

@dataclass
class CreateSecretsOptions:
    env_name: str
    key_value_pairs: List[Dict[str, str]]
    app_name: Optional[str] = None
    app_id: Optional[str] = None
    secret_path: str = "/"

    def __post_init__(self):
        if not self.app_name and not self.app_id:
            raise ValueError("Either app_name or app_id must be provided")

@dataclass
class UpdateSecretOptions:
    env_name: str
    key: str
    value: Optional[str] = None
    app_name: Optional[str] = None
    app_id: Optional[str] = None
    secret_path: str = "/"
    destination_path: Optional[str] = None
    override: bool = False
    toggle_override: bool = False

    def __post_init__(self):
        if not self.app_name and not self.app_id:
            raise ValueError("Either app_name or app_id must be provided")

@dataclass
class DeleteSecretOptions:
    env_name: str
    key_to_delete: str
    app_name: Optional[str] = None
    app_id: Optional[str] = None
    secret_path: str = "/"

    def __post_init__(self):
        if not self.app_name and not self.app_id:
            raise ValueError("Either app_name or app_id must be provided")

@dataclass
class PhaseSecret:
    key: str
    value: str
    comment: str = ""
    path: str = "/"
    tags: List[str] = field(default_factory=list)
    overridden: bool = False
    application: Optional[str] = None
    environment: Optional[str] = None

class Phase:
    def __init__(self, init=True, pss=None, host=None):
        self._phase_io = PhaseIO(init=init, pss=pss, host=host)

    def _resolve_secret_values(self, secrets: List[PhaseSecret], env_name: str, app_name: str) -> List[PhaseSecret]:
        """
        Utility function to resolve secret references within secret values.
        
        Args:
            secrets (List[PhaseSecret]): List of secrets to process
            env_name (str): Environment name for secret resolution
            app_name (str): Application name for secret resolution
            
        Returns:
            List[PhaseSecret]: List of secrets with resolved values
        """
        # Convert PhaseSecret objects to dict format expected by resolve_all_secrets
        all_secrets = [
            {
                'environment': secret.environment or env_name,
                'path': secret.path,
                'key': secret.key,
                'value': secret.value
            }
            for secret in secrets
        ]
        
        # Create new list of secrets with resolved values
        resolved_secrets = []
        for secret in secrets:
            resolved_value = resolve_all_secrets(
                value=secret.value,
                all_secrets=all_secrets,
                phase=self._phase_io,
                current_application_name=secret.application or app_name,
                current_env_name=secret.environment or env_name
            )
            
            resolved_secrets.append(PhaseSecret(
                key=secret.key,
                value=resolved_value,
                comment=secret.comment,
                path=secret.path,
                tags=secret.tags,
                overridden=secret.overridden,
                application=secret.application,
                environment=secret.environment
            ))
            
        return resolved_secrets

    def get_secret(self, options: GetSecretOptions) -> Optional[PhaseSecret]:
        secrets = self._phase_io.get(
            env_name=options.env_name,
            keys=[options.key_to_find] if options.key_to_find else None,
            app_name=options.app_name,
            app_id=options.app_id,
            tag=options.tag,
            path=options.secret_path
        )
        if secrets:
            secret = secrets[0]
            phase_secret = PhaseSecret(
                key=secret['key'],
                value=secret['value'],
                comment=secret.get('comment', ''),
                path=secret.get('path', '/'),
                tags=secret.get('tags', []),
                overridden=secret.get('overridden', False),
                application=secret.get('application'),
                environment=secret.get('environment')
            )

            # Resolve any secret references in the value
            resolved_secrets = self._resolve_secret_values(
                [phase_secret], 
                options.env_name,
                secret.get('application', options.app_name)
            )
            
            return resolved_secrets[0] if resolved_secrets else None
        return None

    def get_all_secrets(self, options: GetAllSecretsOptions) -> List[PhaseSecret]:
        secrets = self._phase_io.get(
            env_name=options.env_name,
            app_name=options.app_name,
            app_id=options.app_id,
            tag=options.tag,
            path=options.secret_path
        )
        
        if not secrets:
            return []

        # Get the application name from the first secret
        app_name = secrets[0].get('application', options.app_name)
        
        phase_secrets = [
            PhaseSecret(
                key=secret['key'],
                value=secret['value'],
                comment=secret.get('comment', ''),
                path=secret.get('path', '/'),
                tags=secret.get('tags', []),
                overridden=secret.get('overridden', False),
                application=secret.get('application'),
                environment=secret.get('environment')
            )
            for secret in secrets
        ]
        
        # Resolve any secret references in the values
        return self._resolve_secret_values(
            phase_secrets,
            options.env_name,
            app_name
        )

    def create_secrets(self, options: CreateSecretsOptions) -> str:
        # Convert the list of dictionaries to a list of tuples
        key_value_tuples = [(list(item.keys())[0], list(item.values())[0]) for item in options.key_value_pairs]
        
        response = self._phase_io.create(
            key_value_pairs=key_value_tuples,
            env_name=options.env_name,
            app_name=options.app_name,
            app_id=options.app_id,
            path=options.secret_path
        )
        return "Success" if response.status_code == 200 else f"Error: {response.status_code}"

    def update_secret(self, options: UpdateSecretOptions) -> str:
        return self._phase_io.update(
            env_name=options.env_name,
            key=options.key,
            value=options.value,
            app_name=options.app_name,
            app_id=options.app_id,
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
            app_id=options.app_id,
            path=options.secret_path
        )

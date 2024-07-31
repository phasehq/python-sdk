from dataclasses import dataclass
from typing import List, Dict, Optional
from .utils.phase_io import Phase as PhaseIO
from .utils.secret_referencing import resolve_all_secrets

@dataclass
class PhaseSecret:
    key: str
    value: str
    comment: str
    path: str
    tags: List[str]
    overridden: bool

class Phase:
    def __init__(self, init=True, pss=None, host=None):
        self._phase_io = PhaseIO(init=init, pss=pss, host=host)

    def create(self, env_name: str, app_name: str, secrets: List[PhaseSecret], path: str = '/') -> str:
        key_value_pairs = [(secret.key, secret.value) for secret in secrets]
        response = self._phase_io.create(key_value_pairs, env_name, app_name, path)
        return "Success" if response.status_code == 200 else f"Error: {response.status_code}"

    def get(self, env_name: str, keys: List[str] = None, app_name: str = None, tag: str = None, path: str = '') -> List[PhaseSecret]:
        secrets = self._phase_io.get(env_name, keys, app_name, tag, path)
        phase_secrets = [
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
        return self._resolve_references(phase_secrets, env_name, app_name)

    def update(self, env_name: str, secret: PhaseSecret, app_name: str = None) -> str:
        response = self._phase_io.update(
            env_name, 
            secret.key, 
            secret.value, 
            app_name, 
            source_path=secret.path
        )
        return response

    def delete(self, env_name: str, keys: List[str], app_name: str = None, path: str = None) -> List[str]:
        return self._phase_io.delete(env_name, keys, app_name, path)

    def _resolve_references(self, secrets: List[PhaseSecret], env_name: str, app_name: str) -> List[PhaseSecret]:
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
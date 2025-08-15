import argparse
import pathlib
import sys
from typing import Dict, List, Optional, Any

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator, ConfigDict


class Environment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    branch: str = Field(..., min_length=1, str_strip_whitespace=True)
    enabled: bool = True


class FileToPush(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(..., min_length=1, str_strip_whitespace=True)
    destination: str = Field(..., min_length=1, str_strip_whitespace=True)


class Service(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, str_strip_whitespace=True)
    repo: str = Field(..., min_length=1, str_strip_whitespace=True)
    enabled: bool = True

    workflow_file: str = Field(..., pattern=r".+\.ya?ml$", min_length=1, str_strip_whitespace=True)
    env: Dict[str, str] = Field(default_factory=dict)
    environment_configs: Dict[str, Environment]
    files_to_push: Optional[List[FileToPush]] = None

    @field_validator("environment_configs")
    @classmethod
    def require_at_least_one_environment(cls, value: Dict[str, Environment]):
        if not value:
            raise ValueError("environment_configs must contain at least one environment")
        return value

    @field_validator("files_to_push")
    @classmethod
    def files_nonempty_if_present(cls, value: Optional[List[FileToPush]]):
        if value is not None and len(value) == 0:
            raise ValueError("files_to_push must must contain at least one file when provided")
        return value


class Root(BaseModel):
    model_config = ConfigDict(extra="forbid")

    services: List[Service]

    @field_validator("services")
    @classmethod
    def unique_service_names(cls, value: List[Service]):
        names = [service.name for service in value]
        if len(names) != len(set(names)):
            raise ValueError("service names must be unique")
        return value


def load_yaml(path: pathlib.Path):
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def validate_content(content: Any, path: pathlib.Path):
    if isinstance(content, dict) and "services" in content:
        Root.model_validate(content)
    else:
        Service.model_validate(content)


def main():
    parser = argparse.ArgumentParser(description="Validate service YAML config(s).")
    parser.add_argument("files", nargs="*", help="Paths to YAML files")
    args = parser.parse_args()

    files = [pathlib.Path(p) for p in args.files]
    is_any_errors = False

    for path in files:
        if not path.exists():
            print(f"[error] file={path}, message=Config not found::{path} does not exist")
            is_any_errors = True
            continue

        try:
            data = load_yaml(path)
            validate_content(data, path)
            print(f"[OK] {path} is valid")
        except ValidationError as e:
            is_any_errors = True
            for err in e.errors():
                print(f"[error] file={path}, message=Config validation::{err.get('loc')}: {err.get('msg')}")
        except yaml.YAMLError as ye:
            is_any_errors = True
            print(f"[error] file={path}, message=YAML parse error::{ye}")

    sys.exit(1 if is_any_errors else 0)


if __name__ == "__main__":
    main()

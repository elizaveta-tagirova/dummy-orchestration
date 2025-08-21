import argparse, hashlib, json, os, pathlib, sys, yaml
from jsonschema import validate
from jinja2 import Environment, FileSystemLoader, StrictUndefined
import re

def regex_replace(value, pattern, replacement):
    return re.sub(pattern, replacement, value)

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def add_header(rendered: str, source: str) -> str:
    """Insert the checksum line after rendering. The template includes placeholders for source & checksum."""
    # Calculate checksum of the payload (everything after checksum line).
    # For simplicity, we compute checksum over the lines AFTER the checksum header.
    # Here we temporarily put a placeholder, then replace it.
    placeholder = "{{CHECKSUM}}"
    rendered = rendered.replace("{{ checksum }}", placeholder).replace("{{checksum}}", placeholder)
    # find the start of payload (after the line that contains 'checksum:')
    lines = rendered.splitlines(True)
    payload_started = False
    payload = []
    saw_checksum = False
    for ln in lines:
        if "checksum:" in ln:
            saw_checksum = True
        elif saw_checksum and (ln.strip().startswith("#") or ln.strip().startswith("//")):
            # comments following checksum still considered header until a non-comment or blank? keep simple:
            pass
        elif saw_checksum:
            payload_started = True
        if payload_started:
            payload.append(ln)
    payload_bytes = "".join(payload).encode()
    sumhex = sha256_bytes(payload_bytes)
    return rendered.replace(placeholder, sumhex).replace("{{ source }}", source)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--schema", required=True)
    p.add_argument("--values", required=True)
    p.add_argument("--templates", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()

    # root = pathlib.Path(".").resolve()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    with open(args.values, "r", encoding="utf-8") as f:
        values = yaml.safe_load(f)
    with open(args.schema, "r", encoding="utf-8") as f:
        schema = json.load(f)
    validate(values, schema)

    jinja_env = Environment(
        loader=FileSystemLoader(args.templates),
        autoescape=False,
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        lstrip_blocks=True,
        trim_blocks=True,
    )
    jinja_env.filters["regex_replace"] = regex_replace

    # Provenance
    # source = os.environ.get("B_SOURCE", "repo-b@<unknown-ref> " + args.values)
    source = "repo B"

    # Render files
    def render_to(tpl_name, target):
        tpl = jinja_env.get_template(tpl_name)
        rendered = tpl.render(**values, source=source, checksum="{{checksum}}")
        final = add_header(rendered, source)
        pathlib.Path(target).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(target).write_text(final, encoding="utf-8")

    render_to("env.tpl.j2", out / "env")
    render_to("gradle-block.tpl.j2", out / "gradle-block")


if __name__ == "__main__":
    main()

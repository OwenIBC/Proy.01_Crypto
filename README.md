# Secure Digital Document Vault

Bóveda de documentos con cifrado autenticado para un único propietario.

## Estado de entregables

| Entregable | Contenido | Documentación |
|---|---|---|
| **D2** — Cifrado simétrico | AES-256-GCM (o ChaCha20-Poly1305) con *envelope encryption*, metadatos autenticados como AAD | [docs/design_d2.md](docs/design_d2.md) |

## Estructura

```text
vault/
  symmetric.py     # encrypt_file / decrypt_file (+ variantes en memoria)
  exceptions.py    # DecryptionFailedError y errores de validación
tests/
  test_symmetric.py
docs/
  design_d2.md     # diseño, justificación de seguridad, modelo de amenazas, flujo Git
```

## Instalación

Requiere Python ≥ 3.10.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
```

> Si tu distribución no incluye `ensurepip` (error *"ensurepip is not available"*), instala `python3-venv`
> o crea el entorno con `python3 -m venv --without-pip .venv` e inicializa pip con
> `curl -sSfLO https://bootstrap.pypa.io/get-pip.py && .venv/bin/python get-pip.py`.

## Uso

```python
from pathlib import Path
from vault import encrypt_file, decrypt_file, generate_owner_key, DecryptionFailedError

kek = generate_owner_key()  # 32 bytes del CSPRNG del SO; guárdala de forma segura

encrypt_file(Path("contrato.pdf"), kek, Path("contrato.pdf.vault"),
             metadata={"caso": "2026-17"})          # metadatos autenticados, NO cifrados

try:
    decrypt_file(Path("contrato.pdf.vault"), kek, Path("contrato_restaurado.pdf"))
except DecryptionFailedError:
    print("Contenedor inválido, manipulado o clave incorrecta")  # no se escribe nada en disco
```

Opciones: `algorithm="ChaCha20-Poly1305"` y `include_filename=False` (para no guardar el nombre original en claro).
Las rutas de salida nunca se sobrescriben (`FileExistsError`).

## Pruebas

```bash
.venv/bin/python -m pytest -v
```

## Seguridad en una línea

Cada byte del contenedor (`magic | len | header | wrap_nonce | wrapped_dek | payload_nonce | ciphertext | tag`)
está cubierto por un tag AEAD; cualquier alteración produce un `DecryptionFailedError` genérico sin salida en
disco. Ver el modelo de amenazas y lo que queda **fuera de alcance** (replay/rollback, confidencialidad de
metadatos, gestión de la KEK) en [docs/design_d2.md](docs/design_d2.md#33-modelo-de-amenazas).

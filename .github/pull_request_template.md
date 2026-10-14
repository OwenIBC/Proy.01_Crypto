## Resumen

<!-- ¿Qué entregable/cambio implementa este PR? -->

## Lista de verificación criptográfica (revisor)

- [ ] Sólo se usan primitivas de `cryptography` (nada implementado a mano).
- [ ] Toda la aleatoriedad proviene de `os.urandom` / `secrets` (nunca `random`, ni semillas fijas).
- [ ] Ningún par (clave, nonce) puede repetirse; DEK nueva por archivo.
- [ ] Metadatos y parámetros del formato están ligados como AAD.
- [ ] Los fallos de descifrado lanzan `DecryptionFailedError` genérico, sin encadenar la causa.
- [ ] No se escribe texto plano sin verificar; sin archivos temporales ni residuos tras un fallo.
- [ ] No hay claves, contenedores reales ni secretos en el diff.
- [ ] Pruebas nuevas/actualizadas y CI en verde.
- [ ] Documentación (`docs/`) actualizada, incluido el modelo de amenazas.


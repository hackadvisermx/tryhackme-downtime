# The Waiting Room

## Estado

- **Tipo:** CTF / Team room.
- **URL:** [The Waiting Room](https://tryhackme.com/room/thewaitingroom).
- **Dificultad:** Medium.
- **Duración estimada:** 45 minutos.
- **Resultado:** sala completada correctamente; TryHackMe mostró `Room completed`.
- **Fecha de trabajo:** 24 de octubre de 2026.
- **Actividad del evento:** #5 de 8; segundo CTF completado (`Challenges: 2/5`).

> El análisis fue estático. No se ejecutaron el HTA, el JavaScript descargado ni
> el documento transferido. Los archivos de evidencia permanecieron en la
> máquina del laboratorio y no se añadieron al repositorio.

## Objetivo

La investigación parte de un correo dirigido a Michelle Smith con un adjunto
de OneNote. Había que correlacionar tres fuentes para reconstruir la cadena:

1. `vendor.eml`, para identificar y extraer el adjunto;
2. `Sysmon-incident.evtx`, para seguir la ejecución en Windows;
3. `incident.pcap`, para recuperar el stage descargado y el documento enviado.

La cadena resultante fue: adjunto OneNote con HTA embebido → ejecución mediante
`cscript.exe` → descarga cifrada de `remittance-v2.png` → ejecución de
`receipt.js` → lectura y cifrado de `payment-register.csv` → POST a
`/api/receipt`.

## Cadena de ejecución

### 1. Correo y adjunto

El correo `vendor.eml` contiene el archivo `Remittance.one`. El hash del
contenedor OneNote completo es `393d80fb5a56484ccb615c8fc70c5f3009457b62a281788b5dfa79c209ec8669`,
pero no es la respuesta de la primera pregunta: TryHackMe pide el SHA-256 del
payload HTML/HTA embebido.

El contenido del OneNote revela el nombre visual engañoso:

```text
Remittance_\u202efdp.hta
```

El carácter `U+202E` es **RIGHT-TO-LEFT OVERRIDE**. La inversión visual hace
que el archivo parezca un documento PDF, aunque termina en `.hta`.

El payload se delimitó desde `<!DOCTYPE html>` hasta `</html>` dentro del
contenedor. Esos bytes ocupan 1866 bytes y su SHA-256 es:

```text
e3e53f2e21df0b56eeb62d50146c4d69eb8cbc1badb5b8ba13f8ba5859870f6b3
```

### 2. Eventos de Windows

Sysmon registra un PowerShell padre con PID `2028` y `-EncodedCommand`, pero
el proceso que ejecuta el script descargado es el intérprete correcto para la
pregunta de la sala:

```text
ProcessId=1996
Image=C:\Windows\SysWOW64\cscript.exe
User=MERIDIAN\m.smith
```

La distinción entre el padre PowerShell (`2028`) y `cscript.exe` (`1996`) es
importante: la respuesta validada es **1996**.

El host observado en los eventos y en el tráfico es:

```text
portal.meridian.thm
```

### 3. Descarga y descifrado del stage

La HTA usa cadenas ofuscadas con valores hexadecimales y un XOR estático con
`0x39`. Al decodificarlas aparecen, entre otros, estos indicadores:

```text
MSXML2.XMLHTTP.6.0
Scripting.FileSystemObject
WScript.Shell
http://portal.meridian.thm:8080/assets/remittance-v2.png
%LOCALAPPDATA%\Meridian\receipt.js
cscript.exe //B //Nologo
MR-6106-028
```

El archivo llamado `.png` es un stage cifrado, no una imagen. La clave
encontrada en la HTA y validada por la sala es:

```text
3c7a8c88466f5b869bea15f333e3be01
```

El descifrado estático con esa clave produce `receipt.js`. El script lee
`%USERPROFILE%\Documents\Finance\payment-register.csv`, cifra su contenido
con el mismo esquema RC4-equivalente, lo codifica en Base64 y lo envía por
HTTP.

### 4. Exfiltración

En `incident.pcap`:

- el stream TCP 8 descarga `GET /assets/remittance-v2.png` desde
  `portal.meridian.thm:8080`;
- el stream TCP 9 envía `POST /api/receipt` con `Content-Type: application/json`;
- el JSON incluye el documento `payment-register.csv`, la referencia
  `MR-6106-028`, la workstation `MERIDIAN` y el usuario `m.smith`.

Después de descifrar el campo del documento con la misma clave, su SHA-256 es:

```text
c19c4964c2a77872c49750cc1c2dd443b48fba984b41988aec6fbc780faed09a
```

## Respuestas validadas

| # | Pregunta | Respuesta |
|---|---|---|
| 1 | SHA-256 del adjunto embebido | `e3e53f2e21df0b56eeb62d50146c4d69eb8cbc1badb5b8ba13f8ba5859870f6b3` |
| 2 | Código Unicode del carácter de inversión | `U+202E` |
| 3 | Hostname observado | `portal.meridian.thm` |
| 4 | PID del intérprete que ejecutó el script | `1996` |
| 5 | Clave de cifrado | `3c7a8c88466f5b869bea15f333e3be01` |
| 6 | SHA-256 del documento transferido | `c19c4964c2a77872c49750cc1c2dd443b48fba984b41988aec6fbc780faed09a` |

## Método de análisis

Los artefactos estaban en `~/Desktop/artifacts` dentro del laboratorio:

```text
vendor.eml
Sysmon-incident.evtx
incident.pcap
tools/evtx_dump
tools/cyberchef
```

Conversión del EVTX y búsqueda del proceso:

```bash
~/Desktop/artifacts/tools/evtx_dump \
  ~/Desktop/artifacts/Sysmon-incident.evtx > /tmp/sysmon.xml
grep -i -n -B4 -A8 'cscript\|wscript\|receipt.js' /tmp/sysmon.xml
```

Extracción del payload embebido y cálculo de su hash:

```bash
python3 - <<'PY'
import hashlib
import re

data = open('/tmp/remittance.one', 'rb').read()
match = re.search(br'<!DOCTYPE html>.*?</html>', data, re.I | re.S)
payload = match.group(0)
print(len(payload))
print(hashlib.sha256(payload).hexdigest())
PY
```

Inspección de los streams relevantes:

```bash
tshark -r ~/Desktop/artifacts/incident.pcap \
  -Y 'tcp.stream==8 && tcp.srcport==8080 && tcp.payload'
tshark -r ~/Desktop/artifacts/incident.pcap -q -z follow,tcp,ascii,9
```

La recuperación del stage, su descifrado RC4-equivalente y la reconstrucción
del JSON se hicieron sin ejecutar ninguno de los scripts.

## Validación en TryHackMe

Las seis preguntas fueron aceptadas. Tras la sexta respuesta, TryHackMe
redirigió a `thewaitingroom/congratulations?step=records` y mostró:

```text
Great work hackadvisermx! Room completed!
```

El siguiente reto del evento es [Day-O](https://tryhackme.com/jr/dayo).

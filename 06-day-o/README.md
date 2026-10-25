# Day-O

## Estado

- **Tipo:** CTF / Team room.
- **URL:** [Day-O](https://tryhackme.com/room/dayo).
- **Dificultad:** Medium.
- **Duración estimada:** 45 minutos.
- **Resultado:** sala completada correctamente; TryHackMe mostró `Room completed`.
- **Fecha de trabajo:** 24 de octubre de 2026.
- **Actividad del evento:** #6 de 8; tercer CTF completado (`Challenges: 3/5`).

> El análisis se hizo sobre la captura de memoria proporcionada por el
> laboratorio. No se ejecutó el payload ni el script PowerShell; la caché se
> descifró de forma estática. La captura de 4 GB y los archivos extraídos no
> se añadieron al repositorio.

## Objetivo

Reconstruir qué ocurrió en una sesión de revisión documental a partir de una
captura de memoria de Windows: identificar el proceso sospechoso, localizar la
región ejecutable privada, recuperar los artefactos asociados, analizar el
payload oculto y recuperar la información dejada en la caché cifrada.

La cadena reconstruida fue:

```text
ReviewClient.exe
  └─ región privada PAGE_EXECUTE_READWRITE en 0x8e0000
      └─ shellcode con resolvedor de exports y llamada a kernel32.WinExec
          └─ payload añadido después del IEND de review-cover.png
              └─ PowerShell con AES-CBC/PKCS7
                  └─ review-cache.dat → review-cache.zip → approval.txt
```

## 1. Proceso y región ejecutable

La enumeración de procesos con Volatility identificó el proceso relevante:

```text
PID       PPID      Image
6260      6164      ReviewClient.exe
```

La inspección de VADs para el PID `6260` mostró una región privada con
permisos `PAGE_EXECUTE_READWRITE`:

```text
Start      End        Tag   Protection             File
0x8e0000  0x8e0fff   VadS  PAGE_EXECUTE_READWRITE  N/A
```

La región comienza en `0x8e0000`, no en la imagen mapeada de
`ReviewClient.exe`.

Comandos principales:

```bash
~/Desktop/artifacts/tools/venv/bin/vol \
  -f ~/Desktop/artifacts/memory.mem \
  --offline -s ~/Desktop/artifacts/symbols \
  windows.pslist

~/Desktop/artifacts/tools/venv/bin/vol \
  -f ~/Desktop/artifacts/memory.mem \
  --offline -s ~/Desktop/artifacts/symbols \
  windows.vadinfo --pid 6260

~/Desktop/artifacts/tools/venv/bin/vol \
  -f ~/Desktop/artifacts/memory.mem \
  --offline -s ~/Desktop/artifacts/symbols \
  windows.malfind --pid 6260
```

`windows.malfind` confirmó instrucciones ejecutables en esa región. El
desensamblado forma en la pila la cadena `WinExec` y usa un resolvedor basado
en el PEB para encontrar la API antes de invocarla.

## 2. Archivos asociados y payload del PNG

Los handles abiertos por `ReviewClient.exe` incluyeron:

```text
\Users\s.reyes\Downloads\DocumentReview\review-cache.dat
\Users\s.reyes\Downloads\DocumentReview\review-cover.png
```

La extracción con `windows.dumpfiles` produjo una copia válida de
`review-cover.png` y el archivo de caché. La imagen tiene dimensiones
`1000 x 620` y un `IEND` válido; inmediatamente después del CRC de `IEND`
aparecen bytes ejecutables que comienzan con el mismo prólogo observado en la
región privada:

```text
55 89 e5 83 ec 18 31 f6 56 6a 63 66 68 78 65 ...
```

Esto describe un payload embebido como overlay después del final lógico del
PNG. La sub-técnica ATT&CK validada por la sala es `T1027.009` (Embedded
Payloads).

El payload resuelve y llama a:

```text
kernel32.WinExec
```

La respuesta completa requerida por TryHackMe incluye el módulo y la API;
`WinExec` por sí solo no fue aceptado.

## 3. Stage PowerShell y descifrado de la caché

El shellcode decodifica un comando y lo pasa a `WinExec`. El comando resultante
es un PowerShell con una cadena Base64 que contiene el siguiente stage:

```powershell
$k=[Convert]::FromBase64String('fXFKcmfoirwa/SI4MMt018hA9nf/Fl++ycE0WV8G+qg=')
$b=[IO.File]::ReadAllBytes('review-cache.dat')
$a=[Security.Cryptography.Aes]::Create()
$a.Key=$k
$a.IV=$b[0..15]
$a.Mode='CBC'
$a.Padding='PKCS7'
$d=$a.CreateDecryptor().TransformFinalBlock($b,16,$b.Length-16)
[IO.File]::WriteAllBytes('review-cache.zip',$d)
```

La clave Base64 se decodifica a 32 bytes, representados en el formato que
espera la sala como 64 caracteres hexadecimales:

```text
7d714a7267e88abc1afd223830cb74d7c840f677ff165fbec9c134595f06faa8
```

El primer bloque de `review-cache.dat` es el IV. El resto se descifra con
AES-CBC y padding PKCS#7, produciendo un ZIP con:

```text
release/approval.txt
release/contacts.csv
```

`release/approval.txt` contiene la referencia de aprobación y la flag:

```text
INTERNAL - DOCUMENT CONTROL
Prepared by Michelle Smith
Reviewer: Sophia Reyes
Approval reference: THM{2b3cc75adab999202e1879af542b2c11}
Do not distribute externally.
```

## Respuestas validadas

| # | Pregunta | Respuesta |
|---|---|---|
| 1 | Ejecutable que contiene el payload | `ReviewClient.exe` |
| 2 | Dirección virtual inicial de la región privada | `0x8e0000` |
| 3 | Archivo asociado que contiene el mismo payload | `review-cover.png` |
| 4 | Sub-técnica MITRE ATT&CK | `T1027.009` |
| 5 | API de Windows que lanza el siguiente stage | `kernel32.WinExec` |
| 6 | Clave AES en hexadecimal | `7d714a7267e88abc1afd223830cb74d7c840f677ff165fbec9c134595f06faa8` |
| 7 | Flag | `THM{2b3cc75adab999202e1879af542b2c11}` |

## Método de análisis reproducible

Enumeración de módulos y handles relevantes:

```bash
~/Desktop/artifacts/tools/venv/bin/vol \
  -f ~/Desktop/artifacts/memory.mem \
  --offline -s ~/Desktop/artifacts/symbols \
  windows.dlllist --pid 6260

~/Desktop/artifacts/tools/venv/bin/vol \
  -f ~/Desktop/artifacts/memory.mem \
  --offline -s ~/Desktop/artifacts/symbols \
  windows.handles --pid 6260

~/Desktop/artifacts/tools/venv/bin/vol \
  -f ~/Desktop/artifacts/memory.mem \
  --offline -s ~/Desktop/artifacts/symbols \
  windows.dumpfiles --pid 6260
```

Para validar que el archivo recuperado era una imagen y localizar el overlay:

```bash
file review-cover.png.dat
xxd -g1 -l 32 review-cover.png.dat
```

La extracción del overlay se hizo buscando el chunk `IEND` del PNG y
analizando los bytes posteriores como shellcode. La caché se descifró con la
clave anterior, usando como IV sus primeros 16 bytes, sin ejecutar el contenido
recuperado.

## Validación en TryHackMe

Las siete respuestas fueron aceptadas. TryHackMe mostró `Room completed: 100%`
y redirigió a la pantalla de felicitación. Después se terminaron tanto la
AttackBox como la máquina de laboratorio de Day-O; la página confirmó
`Your machine has been terminated successfully`.

El siguiente reto del evento es [Strange & Unusual Activity](https://tryhackme.com/jr/strangeunusualactivity).

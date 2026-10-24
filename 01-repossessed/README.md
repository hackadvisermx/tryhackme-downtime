# Repossessed — SOC Simulator

Estado: **completado**. El escenario se inició con **Splunk**, se cerraron las
nueve alertas y TryHackMe mostró `Repossessed (Completed)` junto con el pase
del SOC Simulator.

## Objetivo

Investigar la actividad anómala de una estación de Marketing, determinar cómo
se ejecutó el código, comprobar la comunicación externa, identificar posibles
pasos hacia otros sistemas y establecer si hubo acceso o extracción de datos.

## Flujo del simulador

1. Esperar a que se genere la cola de alertas.
2. Tomar la propiedad de cada alerta antes de investigarla.
3. Correlacionar el detalle del evento con el SIEM y la VM de análisis.
4. Clasificar cada alerta como true positive o false positive.
5. Escribir el razonamiento, la evidencia y las acciones en el case report.
6. Revisar el resultado y el feedback de MTTR/puntuación.

La documentación del simulador advierte que las alertas llegan con retrasos
intencionales para imitar un flujo SOC real. En esta ejecución no había un
worker persistente: se hicieron comprobaciones activas hasta que el contador
quedó en `0 alerts incoming` y aparecieron las cuatro alertas finales.

## Primer lote observado

La cola anunció nueve alertas. El primer lote visible contenía cuatro alertas,
todas de severidad alta, asociadas a `THM-MSMITH.tryhatmestudios.thm` y al
usuario `TRYHATME\m.smith`. Después apareció la alerta 6356, también de alta
severidad, relacionada con descubrimiento del dominio y los hosts.

En TryHackMe quedaron cerradas las alertas **6352–6360**. La 6352 se revisó
posteriormente y quedó corregida como falso positivo; las 6353–6360 se
registraron como verdaderos positivos con escalamiento.

| ID | Regla | Tipo | Clasificación provisional | Evidencia principal |
|---:|---|---|---|---|
| 6353 | Suspicious Child Process Spawned | Execution | **True positive** | `WINWORD.EXE` abrió `Q3_PressKit_Feedback.docm` y lanzó PowerShell oculto con `-Enc`. |
| 6354 | Suspicious Outbound Connection Following Document Execution | Command and Control | **True positive** | El mismo PowerShell (`PID 8572`) conectó desde `10.60.10.22` a `45.147.230.131:8067`. |
| 6355 | Anomalous Credential Vault Access | Credential Access | **True positive** | `vaultcmd.exe /listcreds:Windows Credentials` fue hijo del PowerShell descargado. |
| 6352 | Suspicious Child Process Spawned | Execution | **False positive** | `ai.exe` de Microsoft Office fue lanzado por Word como componente Local AI legítimo. |
| 6356 | Rapid Domain and Host Enumeration from Non-Administrative Host | Discovery | **True positive** | `net.exe user /domain` fue ejecutado por el mismo PowerShell oculto (`PID 9356`) desde la estación de Marketing. |
| 6357 | Suspicious Remote Logon and Service Creation | Lateral Movement | **True positive** | En `THM-SREYES` el usuario `TRYHATME\\svc-mktshare` instaló el servicio `SvcUpdate`, ejecutado como `LocalSystem`, para lanzar el stager oculto. |
| 6358 | Suspicious External Connection Following Archive Creation | Exfiltration | **True positive** | PowerShell (`PID 12408`) conectó desde `10.60.10.20` a `104.18.32.47:443`; el destino HTTPS apareció alrededor de la creación del archivo comprimido. |
| 6359 | Suspicious Archive Utility Execution on Workstation | Collection | **True positive** | `7z.exe` comprimió `C:\Dev\NeuralNexus\Build\*` en `C:\Windows\Temp\nx_build_beta.7z`; el padre fue el PowerShell oculto como `SYSTEM`. |
| 6360 | Suspicious External Connection Following Archive Creation | Exfiltration | **True positive** | PowerShell (`PID 14264`) conectó desde `10.60.10.20` a `45.147.230.131:8067`, el mismo destino/puerto del stager, después de crear el archivo. |

## Cadena provisional

La evidencia disponible permite reconstruir esta secuencia:

```text
Q3_PressKit_Feedback.docm
        └─ WINWORD.EXE
             └─ powershell.exe -NoP -W Hidden -Enc <Base64 UTF-16LE>
                  ├─ descarga %TEMP%\svchost_update.ps1
                  │  desde payblink-cdn.thm:8067
                  ├─ ejecuta un segundo PowerShell oculto
                  │  con ExecutionPolicy Bypass
                  └─ consulta las credenciales del almacén de Windows
                        └─ crea SvcUpdate como LocalSystem
                             └─ enumera el dominio, comprime la build
                                  y transmite datos a destinos externos
```

La conexión inicial observada usó TCP desde el host `10.60.10.22:54331` hacia
`45.147.230.131:8067`, con PowerShell como proceso iniciador. En el host
`THM-SREYES` se observaron después la creación de `nx_build_beta.7z`, una
conexión HTTPS a `104.18.32.47:443` y otra conexión a
`45.147.230.131:8067`, formando una cadena coherente de ejecución, colección
y exfiltración.

## Evidencia registrada

- **Proceso padre:** `C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE`.
- **Documento:** `C:\Users\m.smith\Downloads\Q3_PressKit_Feedback.docm`.
- **Usuario:** `TRYHATME\m.smith`.
- **PowerShell:** `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`.
- **Evento de creación:** Sysmon `ProcessCreate`, `event_id` 46148, a las
  `10/24/2026 23:37:30.621`.
- **Conexión:** Sysmon `NetworkConnect`, `event_id` 46159, a las
  `10/24/2026 23:37:33.621`.
- **Acceso a credenciales:** `vaultcmd.exe`, evento de creación `event_id`
  46167, a las `10/24/2026 23:37:34.621`.
- **Descubrimiento:** `net.exe user /domain`, evento `event_id` 46239, a las
  `10/24/2026 23:42:34.621`, con PowerShell `PID 9356` como proceso padre.
- **Movimiento lateral/persistencia:** evento Security `4697`, a las
  `10/24/2026 23:45:04.621`, servicio `SvcUpdate`, cuenta
  `TRYHATME\\svc-mktshare`, `Logon ID 0x24F6572`, ejecución como `LocalSystem`.
- **Colección:** `7z.exe` versión `24.09`, proceso `PID 9104`, a las
  `10/24/2026 23:51:55.621`, en `THM-SREYES`; creó
  `C:\\Windows\\Temp\\nx_build_beta.7z` desde `C:\\Dev\\NeuralNexus\\Build\\*`.
- **Exfiltración/HTTPS:** PowerShell `PID 12408`, desde `10.60.10.20`, hacia
  `104.18.32.47:443`, a las `10/24/2026 23:50:04.621`.
- **Exfiltración/C2:** PowerShell `PID 14264`, desde `10.60.10.20`, hacia
  `45.147.230.131:8067`, a las `10/24/2026 23:53:00.621`.

## Resultado y validación

- Se tomaron y cerraron las alertas **6352–6360**.
- Clasificación final: **1 falso positivo** (`6352`) y **8 verdaderos
  positivos** (`6353–6360`).
- Las alertas verdaderas se escalaron; el informe final documentó ejecución,
  C2, acceso a credenciales, descubrimiento, creación de servicio, colección y
  exfiltración.
- TryHackMe marcó `Repossessed (Completed)`, concedió el pase del **SOC
  Simulator** al equipo y otorgó un ticket de rifa personal por el escenario.


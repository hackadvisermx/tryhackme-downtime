# Deadmen Tell No Logs

## Estado

- **Tipo:** Tabletop Exercise.
- **Título mostrado por el simulador:** `Dead on Arrival`.
- **Resultado:** ejercicio completado correctamente.
- **Puntuación narrativa:** **122/150**.
- **Participantes:** 1; ejecución individual como `hackadvisermx` en el equipo
  `hackuaz`.
- **Resumen final:** 14 fases, promedio del equipo 82%, fase más fuerte
  `Triage` (100%) y fase más débil `Detection & Investigation` (67%).
- **Estado del leaderboard:** `Tabletop: Completed`; el equipo quedó con
  `SOC Simulator: Passed`, `TH Simulator: Passed`, **1500 XP** y 3/8
  actividades confirmadas.
- **Fecha de trabajo:** 24 de octubre de 2026.

> El lobby anunciaba 15 fases, mientras que el resumen final mostró 14. Se
> conserva aquí el número que reportó la pantalla de conclusión. No se guardan
> credenciales, tokens ni valores sensibles del simulador.

## Objetivo y contexto

La historia presenta a **NeuralNexus**, un estudio que se prepara para lanzar
una build a las 17:00 UTC. El grupo **Pinstripe Moth** ya tiene presencia en la
red y usa credenciales válidas para intentar alterar la cadena de compilación,
destruir respaldos y suplantar las comunicaciones públicas del lanzamiento.

El tabletop mide la calidad y oportunidad de las decisiones: severidad,
investigación, contención, recuperación y comunicación con las partes
responsables. No hay flags que introducir en esta actividad; el avance se
refleja al completar el ejercicio y el equipo recibe 500 puntos del evento.

## Evidencia inicial y alcance

- **Endpoint externo observado:** `45.147.230.131`.
- **Equipo inicialmente relacionado:** `THM-SREYES`.
- **Hosts de la respuesta:** `BUILD-01`, `BAK-01`, `CI-01` y `FS-ARCHIVE`.
- **Cuenta comprometida:** `svc-studioops`.
- **Cuenta creada para persistencia/privilegios:** `backup-svc`.
- **Tareas relevantes:** `BackupMaintenance` y `DeployPrep`.
- **Artefacto destructivo:** `C:\Windows\Temp\purge-artifacts.ps1`.
- **Ubicación sensible:** `C:\Backups`.
- **Eventos útiles:** 4698 (tarea programada), 4720 (cuenta creada), 4732
  (membresía en grupo) y eventos nativos de Windows para procesos, red y
  sesiones remotas.

La secuencia de ataque fue: reutilización de `svc-studioops` desde
`THM-SREYES` hacia `BUILD-01`, movimiento remoto a `BAK-01`, creación de
`backup-svc` dentro de `Backup Operators`, manipulación de tareas de respaldo,
suplantación de la cuenta social oficial y preparación de un reemplazo de la
build firmada antes de la hora de lanzamiento.

## Decisiones tomadas

| # | Fase | Decisión aplicada | Resultado del simulador |
|---:|---|---|---|
| 1 | Acceso inicial | Declarar incidente High e involucrar a Dana Brooks y Jada Collins para revisar la sesión en `BUILD-01` y la integridad del pipeline. | Más efectiva |
| 2 | Investigación | Extraer y poner en triage los tres eventos de Security sin revisar del intervalo 09:42–09:45 en `BUILD-01`. | Más efectiva |
| 3 | Contención | Rotar la contraseña de `svc-studioops` en Jenkins y limitar la cuenta a `CI-01`. | Más efectiva |
| 4 | Recuperación | Actualizar la nueva contraseña en pipeline, vault y tareas programadas. | Parcialmente efectiva; primero convenía auditar tareas y scripts y retirar persistencia no reconocida. |
| 5 | Escalamiento | Informar a Dana Brooks y a liderazgo de que el atacante alcanzó el host de build y podía afectar la release. | Más efectiva |
| 6 | Segundo incidente | Declarar P0/Critical e involucrar a liderazgo, respuesta, Comms y Legal por el movimiento a `BAK-01` y la cuenta social suplantada. | Más efectiva |
| 7 | Investigación | Analizar las consultas de permisos sobre la tarea de `svc-studioops` y `C:\Backups` en `BAK-01`. | Parcialmente efectiva; los eventos nativos de Windows de `BUILD-01` daban mejor visibilidad. |
| 8 | Contención | Deshabilitar `svc-studioops` y terminar las sesiones WinRM activas entre `BUILD-01` y `BAK-01`. | Razonable, pero la recuperación directa de la cuenta social y el aislamiento de hosts tenían mayor prioridad. |
| 9 | Recuperación | Validar los datos de backup de `BAK-01` contra checksums conocidos antes de restaurar o reconstruir. | Más efectiva |
| 10 | Escalamiento | Actualizar a liderazgo, Legal y PR sobre la suplantación pública y los respaldos disponibles. | Efectiva; la retirada directa del mensaje mediante la plataforma social era la opción óptima. |
| 11 | Objetivo final | Declarar P0/Critical por la destrucción de respaldos y la build maliciosa preparada, incluyendo a las áreas de decisión del lanzamiento. | Más efectiva |
| 12 | Investigación | Extraer y analizar el payload de `DeployPrep` para conocer qué se intentaría publicar a las 16:55. | Efectiva; el barrido global de logons, WinRM y tareas habría dado mayor alcance. |
| 13 | Contención | Deshabilitar `BackupMaintenance` y detener `purge-artifacts.ps1` antes de las 11:37. | Más efectiva |
| 14 | Recuperación | Copiar el último punto de restauración a almacenamiento offline segregado y verificar su checksum. | Más efectiva |
| 15 | Escalamiento final | Informar al comité de lanzamiento sobre el reemplazo preparado, la pérdida de respaldos y la contención para decidir el go/no-go de las 17:00. | Más efectiva |

## Resultado narrativo

Las acciones de contención permitieron detener `DeployPrep` y
`BackupMaintenance` a tiempo. La build staged fue comparada con el hash
firmado por QA y el último punto de restauración se protegió fuera de
`BAK-01`. NeuralNexus pudo salir a las 17:00 UTC con una build no manipulada y
los respaldos intactos.

La comunicación con el comité de lanzamiento permitió que liderazgo y Comms
se anticiparan a la cuenta social secuestrada. El caso pasó después al equipo
de crisis para continuar la recuperación y la investigación.

## Lecciones operativas

1. Un login válido fuera del patrón esperado debe elevarse de inmediato cuando
   toca un host de build.
2. Rotar una cuenta no basta: hay que auditar tareas, scripts, vaults y todos
   los consumidores de la cuenta antes de considerarla erradicada.
3. La visibilidad nativa de Windows —procesos, tareas, red y logons— es una
   compensación importante cuando Sysmon no está disponible.
4. Los respaldos deben validarse con checksums y conservarse en una ubicación
   segregada antes de reconstruir el servidor de backup.
5. La recuperación de una cuenta social comprometida debe coordinarse en
   paralelo con Legal, PR y el comité que decide el lanzamiento.

## Validación en TryHackMe

La pantalla final mostró `Nice work completing the exercise!`, puntuación
**122/150** y la conclusión narrativa anterior. Tras la sincronización
asíncrona, la página del evento mostró para `hackuaz`:

```text
SOC Simulator: Passed
TH Simulator: Passed
Tabletop: Completed
Challenges: 0/5
Points: 1500 XP
```

La actividad no utiliza flags; la validación es la finalización del tabletop y
su reflejo en el leaderboard del equipo.

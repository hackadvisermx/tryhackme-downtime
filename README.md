# TryHackMe — It’s Downtime!

Writeups, evidencias y herramientas para resolver el CTF defensivo
**It’s Downtime!**, también presentado en la página del evento como
**Strange & Unusual Activity**.

Este repositorio es un proyecto hijo de la colección local de CTFs y sigue la
organización usada en [`../thecatch-2026`](../thecatch-2026/).

> El alcance se limita a los escenarios y recursos publicados por TryHackMe
> para este evento. Las credenciales, enlaces privados de invitación, secretos
> y cualquier material sensible usado durante la resolución no se conservarán
> en el repositorio.

## Evento original

- **Sitio oficial:** [tryhackme.com/downtime](https://tryhackme.com/downtime)
- **Modalidad:** CTF defensivo, gratuito, guiado por simuladores y jugable en
  equipo o en solitario.
- **Historia:** el grupo **Pinstripe Moth** ha comprometido la red de un
  estudio de videojuegos, ha sustraído una build no publicada y continúa
  operando dentro del entorno.
- **Fechas:** del **jueves 22 al lunes 26 de octubre de 2026**.
- **Horario:** comienza a las **16:00 UTC** del jueves y termina a las
  **23:59 UTC** del lunes.
- **Audiencia:** perfiles defensivos de cualquier nivel, especialmente SOC,
  threat hunting, respuesta a incidentes y detección.
- **Duración orientativa:** unas horas, repartidas libremente durante los cinco
  días.
- **Equipo:** se puede participar solo; el tamaño máximo indicado para un
  equipo es de 20 personas.

## Qué hay que completar

El evento conecta una misma intrusión a través de ocho actividades: dos
simuladores, un ejercicio tabletop y cinco desafíos CTF.

| # | Actividad | Tipo | Qué hay que hacer | Estado |
|---|---|---|---|---|
| 1 | [Repossessed](https://tryhackme.com/soc-sim/scenarios?scenario=repossessed) | SOC Simulator | Triar nueve alertas, separar amenazas reales del ruido y documentar los hallazgos antes de que salga la build. | **Completado** |
| 2 | [Quiet As The Grave](https://tryhackme.com/threat-hunting-sim/scenarios?scenario=quiet-as-the-grave) | Threat Hunting Simulator | Buscar en los logs sin una alerta confirmada, reconstruir la intrusión por etapas y demostrar hasta dónde llegó. | **Completado** |
| 3 | [Deadmen Tell No Logs](https://tryhackme.com/tabletop-exercises/exercises?exercise=6ad661d34d8777bc630645b5) | Tabletop Exercise | Analizar irregularidades durante una fecha límite y tomar decisiones coordinadas de respuesta. | Pendiente |
| 4 | [Handbook For The Recently Compromised](https://tryhackme.com/jr/handbookfortherecentlycompromised) | CTF | Revisar eventos de Windows, identificar procesos y construir la línea temporal de un equipo sospechoso. | Pendiente |
| 5 | [The Waiting Room](https://tryhackme.com/jr/thewaitingroom) | CTF | Correlacionar un correo con adjunto, eventos de Windows y tráfico capturado para reconstruir la cadena de ejecución. | Pendiente |
| 6 | [Day-O](https://tryhackme.com/jr/dayo) | CTF | Analizar una captura de memoria, investigar procesos y artefactos de una aplicación para encontrar el payload oculto. | Pendiente |
| 7 | [Strange & Unusual Activity](https://tryhackme.com/jr/strangeunusualactivity) | CTF | Investigar logs de conexiones y DNS en Kibana, distinguir patrones sospechosos y estimar la cantidad de datos exfiltrados. | Pendiente |
| 8 | [Dead Endpoint](https://tryhackme.com/jr/deadendpoint) | CTF | Reconstruir el compromiso de un servidor Linux, analizar el ejecutable dejado por el atacante y recuperar las imágenes afectadas. | Pendiente |

## Puntuación y recompensas

- Los cinco retos CTF suman **450 puntos** en total.
- El SOC Simulator, el Threat Hunting Simulator y el tabletop aportan **500
  puntos cada uno por equipo** cuando cualquier integrante los supera.
- La puntuación máxima del evento es, por tanto, **1.950 puntos**.
- Cada participante obtiene un ticket personal por cada actividad que complete
  por sí mismo; el webinar para managers concede dos tickets adicionales.
- El equipo con más puntos al cierre gana la clasificación. En caso de empate,
  queda por delante el equipo que terminó antes.
- Quienes participen obtienen un certificado personal cuando su equipo completa
  el evento.

## Estructura prevista

Cada actividad tendrá su propio writeup, evidencias reproducibles y, cuando
sea útil, scripts auxiliares:

```text
tryhackme-downtime/
├── README.md
├── 01-repossessed/
│   └── README.md
├── 02-quiet-as-the-grave/
│   └── README.md
├── 03-deadmen-tell-no-logs/
│   └── README.md
├── 04-handbook-recently-compromised/
│   └── README.md
├── 05-the-waiting-room/
│   └── README.md
├── 06-day-o/
│   └── README.md
├── 07-strange-unusual-activity/
│   └── README.md
└── 08-dead-endpoint/
    └── README.md
```

Los writeups seguirán, en lo posible, este formato:

1. objetivo y contexto;
2. datos o artefactos disponibles;
3. hipótesis y metodología;
4. comandos, consultas y herramientas utilizadas;
5. interpretación de los resultados;
6. evidencia mínima reproducible;
7. estado de validación en TryHackMe.

## Análisis y ruta de resolución

La progresión combina habilidades de blue team y análisis forense. La ruta
sugerida —no una restricción del evento— es:

1. **Repossessed:** familiarizarse con la clasificación de alertas y la
   diferencia entre ruido operativo e indicadores de compromiso.
2. **Quiet As The Grave:** convertir una hipótesis de amenaza en una búsqueda
   sobre logs y una línea temporal.
3. **Deadmen Tell No Logs:** practicar la coordinación y las decisiones de
   respuesta cuando la evidencia todavía es incompleta.
4. **Handbook** y **The Waiting Room:** correlacionar eventos de Windows,
   correo y tráfico de red.
5. **Strange & Unusual Activity:** investigar conexiones y DNS en Kibana y
   medir la posible salida de datos.
6. **Day-O:** pasar al análisis de memoria y artefactos de procesos.
7. **Dead Endpoint:** cerrar con forense de disco Linux, reversing básico y
   recuperación de archivos.

La página del evento estima aproximadamente 30 minutos para el SOC Simulator,
45–60 minutos para la cacería, 30 minutos para el tabletop y 3–4 horas para
los cinco retos CTF. El progreso detallado y las flags se registrarán en los
writeups individuales únicamente después de validar cada actividad.

## Estado actual

**2/8 actividades confirmadas en el leaderboard.** `Repossessed` quedó
completado en TryHackMe después de cerrar las nueve alertas y enviar el case
report. `Quiet As The Grave` quedó validado tras reconstruir y guardar los 9/9
hitos, marcar la hipótesis como `Proven` y enviar el informe generado por el
simulador. El resultado individual fue **939 puntos**; el leaderboard del
evento muestra `SOC Simulator: Passed`, `TH Simulator: Passed` y **1000 XP**
para el equipo `hackuaz`. El detalle técnico se conserva en
[`01-repossessed/README.md`](01-repossessed/README.md) y
[`02-quiet-as-the-grave/README.md`](02-quiet-as-the-grave/README.md). El README
raíz se actualizó con la información visible en la página oficial del evento
el **24 de octubre de 2026**.


# Strange & Unusual Activity

## Estado

- **Tipo:** CTF / Team room.
- **URL:** [Strange & Unusual Activity](https://tryhackme.com/room/strangeunusualactivity).
- **Dificultad:** Medium.
- **Duración estimada:** 45 minutos.
- **Resultado:** sala completada correctamente; TryHackMe mostró `Room completed`.
- **Fecha de trabajo:** 24 de octubre de 2026.
- **Actividad del evento:** #7 de 8; cuarto CTF completado (`Challenges: 4/5`).
- **Máquina:** `Strange_Activity`, terminada después de validar la sala.
- **AttackBox:** no se inició; se trabajó con la VPN del usuario.

> Las respuestas se reportaron individualmente en TryHackMe conforme fueron
> confirmadas. No se guardaron credenciales, tokens ni datos privados del
> laboratorio.

## Objetivo

Investigar 24 horas de tráfico capturado el **7 de octubre de 2025** en la red
`10.10.14.0/24`, usando los logs de Zeek expuestos en Kibana. El objetivo era
identificar el canal de mando y control (C2), localizar el equipo afectado,
medir el intervalo de comunicación y cuantificar la mayor transferencia
saliente.

La interfaz indicada por la sala fue:

```text
http://<MACHINE_IP>:5601
Data view: zeek-*
```

La máquina asignada durante la resolución fue `10.65.137.255`.

## Investigación

### 1. Localizar el dominio anómalo

La agregación de los registros DNS mostró que
`edge-metrics-sync.net` tenía 289 consultas, una frecuencia idéntica a sus
conexiones HTTPS asociadas. Las respuestas DNS resolvían el dominio a
`203.0.113.77`.

Una consulta representativa en Kibana/Elasticsearch fue:

```json
POST /internal/search/es
{
  "params": {
    "index": "zeek-*",
    "body": {
      "size": 10,
      "sort": [{"ts": {"order": "asc"}}],
      "query": {"term": {"query": "edge-metrics-sync.net"}},
      "_source": [
        "@timestamp", "ts", "id.orig_h", "id.resp_h", "id.resp_p",
        "qtype_name", "answers", "rcode_name"
      ]
    }
  }
}
```

El primer registro observado correspondió a:

```text
origen:       10.10.14.160
resolutor:    10.10.14.1:53
dominio:      edge-metrics-sync.net
respuesta A:  203.0.113.77
```

### 2. Confirmar el host y el intervalo

Se filtraron las conexiones HTTPS del host interno hacia el destino resuelto:

```text
id.orig_h: 10.10.14.160
id.resp_h:  203.0.113.77
id.resp_p:  443
service:    ssl
```

El conjunto resultante tuvo 289 conexiones. Los timestamps fueron casi
periódicos: el promedio entre conexiones fue aproximadamente `299.659` s,
con variaciones normales de captura entre `248.091` y `353.756` s. Por ello,
el intervalo nominal solicitado por la sala es **300 segundos**.

### 3. Contar callbacks y medir exfiltración

El conteo de registros `zeek-dns` para el dominio y de conexiones HTTPS al
destino fue de **289** durante la ventana completa de 24 horas.

Para la transferencia saliente se ordenaron las conexiones por `orig_bytes`.
La mayor entrada correspondió a:

```text
origen:      10.10.14.160
destino:     203.0.113.77:443
orig_bytes:  54078822
resp_bytes:  303
```

La diferencia entre los bytes enviados y recibidos es consistente con una
transferencia de datos en una sesión HTTPS que apenas devuelve una respuesta.

## Respuestas validadas

Cada respuesta se envió y validó por separado en TryHackMe inmediatamente
después de obtenerla; el progreso pasó por `20%`, `40%`, `60%`, `80%` y
finalmente `Room completed: 100%`.

| # | Pregunta | Respuesta |
|---|---|---|
| 1 | Dominio del servidor C2 | `edge-metrics-sync.net` |
| 2 | Intervalo de callback | `300` segundos |
| 3 | IP del host comprometido | `10.10.14.160` |
| 4 | Check-ins durante la captura | `289` |
| 5 | Mayor transferencia saliente | `54078822` bytes |

## Método reproducible

La API interna de Kibana permitió consultar el data view y ejecutar búsquedas
sobre los índices Zeek sin exportar los logs al repositorio:

```bash
curl -sS http://<MACHINE_IP>:5601/api/data_views
curl -sS -X POST http://<MACHINE_IP>:5601/internal/search/es \
  -H 'kbn-xsrf: true' \
  -H 'content-type: application/json' \
  --data-raw '<consulta JSON>'
```

Campos útiles para repetir el análisis:

```text
query        # dominio consultado en Zeek DNS
id.orig_h    # host origen
id.resp_h    # destino
id.resp_p    # puerto destino
ts           # timestamp numérico de Zeek
orig_bytes   # bytes enviados por el origen
resp_bytes   # bytes devueltos por el destino
```

## Validación y cierre

TryHackMe mostró:

```text
Great work hackadvisermx! Room completed!
```

Después se terminó la máquina de laboratorio y la página confirmó:

```text
Your machine has been terminated successfully
```

El siguiente reto del evento es [Dead Endpoint](https://tryhackme.com/jr/deadendpoint).

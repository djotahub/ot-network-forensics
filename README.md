# OT Network Forensics: ICS Threat Detection & Analysis

![Scope](https://img.shields.io/badge/Scope-Critical%20Infrastructure%20(OT)-blue?style=flat-square)
![Protocol](https://img.shields.io/badge/Protocol-Modbus%20TCP%20%2F%20Profinet-orange?style=flat-square)
![Focus](https://img.shields.io/badge/Focus-Threat%20Hunting%20%26%20IDS-red?style=flat-square)

## 1. Resumen de la Investigación

Este repositorio documenta el análisis forense de tráfico de red y la ingeniería de detección aplicada a un incidente de seguridad simulado en un entorno de Sistemas de Control Industrial (ICS).

El objetivo del proyecto fue analizar una captura de paquetes (PCAP) proveniente de una red de tecnología operativa (OT) comprometida, identificar anomalías en los protocolos industriales (Modbus/TCP) y desarrollar reglas de detección (IDS signatures) para mitigar amenazas que podrían impactar la disponibilidad y seguridad física de los procesos críticos.

### 1.1 Escenario del Incidente
* **Vertical:** Infraestructura Crítica (Energía/Aguas).
* **Activo Afectado:** Controlador Lógico Programable (PLC) Siemens S7-1200 / Schneider Electric.
* **Vector de Amenaza:** Inyección de comandos no autorizados sobre el protocolo de control (Puerto 502).

## 2. Metodología Forense

El análisis se condujo siguiendo el ciclo de vida de respuesta a incidentes NIST SP 800-61 y las guías de forense digital NIST SP 800-86:

1.  **Adquisición:** Captura de tráfico pasiva para garantizar la integridad de la red OT (sin inyección de latencia).
2.  **Examen (DPI):** Inspección Profunda de Paquetes para disectar la estructura de la trama Modbus (Transaction ID, Unit ID, Function Code).
3.  **Análisis de Anomalías:** Correlación de flujos de tráfico contra la línea base de operación normal.
4.  **Ingeniería de Detección:** Creación de firmas Snort/Suricata basadas en los Indicadores de Compromiso (IoCs) hallados.

## 3. Análisis de Hallazgos (Threat Hunting)

El análisis del archivo PCAP reveló desviaciones críticas en el comportamiento del protocolo de control.

| ID Evento | Tipo de Anomalía | Descripción Técnica | Impacto Potencial |
| :--- | :--- | :--- | :--- |
| **EVT-01** | **Comando de Escritura Anómalo** | Se detectó el uso del Function Code `06` (Write Single Register) proveniente de una IP externa a la HMI autorizada. | Modificación de setpoints operativos (ej. temperatura, presión), riesgo de daño físico a equipos. |
| **EVT-02** | **Escaneo de Registros** | Múltiples peticiones secuenciales de lectura (Function Code `03`) en un intervalo <1s (Reconnaissance). | Mapeo de la memoria del PLC para identificar variables críticas. |
| **EVT-03** | **Violación de Protocolo** | Paquetes TCP malformados dirigidos al puerto 502 intentando explotar vulnerabilidades de la pila IP del PLC. | Denegación de Servicio (DoS) del controlador y parada de planta. |

## 4. Ingeniería de Detección (Reglas IDS)

Como medida de mitigación y monitoreo continuo, se desarrollaron las siguientes reglas de detección para sistemas IDS (Intrusion Detection Systems) como Snort o Suricata.

### Regla A: Detección de Escritura No Autorizada (Modbus)
Alerta cuando una IP que no pertenece a la lista blanca de Ingeniería intenta escribir valores en el PLC.

```snort
alert tcp !$ENGINEERING_SUBNET any -> $PLC_NET 502 (msg:"OT-IDS: Unauthorized Modbus Write Command Detected"; flow:to_server,established; content:"|06|"; offset:7; depth:1; classtype:attempted-admin; sid:1000001; rev:1;)
```
### Regla B: Detección de Reinicio de PLC (Cold Restart)

Alerta crítica ante comandos que intentan reiniciar o detener la CPU del autómata.

```
alert tcp any any -> $PLC_NET 502 (msg:"OT-IDS: CRITICAL - PLC Stop/Reset Command"; content:"|2B|"; offset:7; reference:url,mitre.org/techniques/T0883; sid:1000002; rev:1;)
```

## 5. Recomendaciones de Arquitectura (Modelo Purdue)

Para prevenir la recurrencia de estos incidentes, se recomienda la implementación estricta de la norma **ISA/IEC 62443**:

1. **Segmentación de Red:** Asegurar la separación física o lógica entre la red IT (Nivel 4/5) y la red OT (Nivel 0-3) mediante DMZ Industrial (Nivel 3.5).
    
2. **Micro-segmentación:** Aislar los PLCs críticos en VLANs dedicadas con listas de control de acceso (ACLs) estrictas.
    
3. **Monitoreo Pasivo:** Implementar sensores IDS en modo espejo (SPAN Port) para no afectar la latencia del proceso industrial.
    

## 6. Estructura del Repositorio

- **`/01_Traffic_Analysis`**: Archivos de captura anonimizados (`.pcap`) y reportes de disección de Wireshark (`.csv`/`.pdf`).
    
- **`/02_IDS_Rules`**: Archivos de reglas (`.rules`) listos para despliegue en motores Snort/Suricata.
    
- **`/03_Evidence`**: Capturas de pantalla del análisis de tramas y diagramas de flujo.
    

---

**Rol:** ICS/SCADA Security Analyst

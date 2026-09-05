# Phish-Tracker // Threat Intel & Typosquatting Watcher

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

**Phish-Tracker** es una herramienta de línea de comandos orientada a la **inteligencia de amenazas** y al **monitoreo defensivo de marcas**. Permite detectar dominios *typosquatted* y posibles infraestructuras de phishing que suplantan un dominio objetivo, analizando cientos de variaciones en tiempo real, cruzándolas con señales adicionales (antigüedad WHOIS, Certificate Transparency) y clasificándolas según su nivel de riesgo.

---

## 🧠 ¿Qué es el Typosquatting?

El *typosquatting* (o suplantación por errores tipográficos) es una técnica utilizada por actores maliciosos para registrar dominios con nombres similares a marcas legítimas, aprovechando errores comunes de escritura, homóglifos, cambios de TLD o adición de palabras como `login`, `secure`, etc. Estos dominios se emplean en campañas de phishing, distribución de malware o robo de credenciales.

**Phish-Tracker** automatiza la generación de estas variaciones, verifica si están registradas, si poseen registros DNS que indiquen actividad maliciosa y, opcionalmente, si fueron registradas recientemente o tienen certificados SSL sospechosos.

---

## ✨ Características principales

- ⚡ **Motor de variaciones avanzado y priorizado**:
  - Adición de palabras clave de phishing (`google-login.com`, `verify-google.com`, `googlelogin.com`).
  - **Cambio de TLD** (`google.com` → `google.net`, `google.io`, `google.xyz`...) — una de las técnicas más usadas en campañas reales y ausente en la v1.
  - Sustitución por homóglifos (`google.com` → `g00gle.com`, `g0ogle.com`).
  - Transposición de letras adyacentes (`google.com` → `gogole.com`).
  - Omisión de caracteres (`google.com` → `gogle.com`).
  - Inserción de caracteres (`google.com` → `googgle.com`).
  - El truncado por `--max-variants` respeta este orden de prioridad, así nunca se descartan las variantes más realistas (keywords/TLD) en favor de inserciones ruidosas.

- 🌐 **Análisis DNS asíncrono**:
  - Consulta registros **A** (resolución de IP) y **MX** (servidores de correo) usando `asyncio` y `dnspython`.
  - Concurrencia y timeout configurables por CLI.
  - Soporte para **nameservers personalizados** (`--nameservers 1.1.1.1,8.8.8.8`), útil si el resolutor por defecto rate-limitea con cientos de consultas simultáneas.
  - Manejo robusto de errores por dominio: un fallo individual nunca detiene el escaneo.

- 🕵️ **Enriquecimiento opcional (Threat Intel)**:
  - **`--whois`**: para cada dominio registrado (ALTO/CRÍTICO), consulta su fecha de creación y marca como *"registro reciente"* los dominios de menos de 30 días — una señal muy fuerte de campaña de phishing activa. Se ejecuta con concurrencia reducida para no saturar los servidores WHOIS.
  - **`--crtsh`**: consulta los logs públicos de **Certificate Transparency** (crt.sh) en busca de dominios reales (no generados por el motor) que tengan certificados SSL emitidos mencionando tu marca — detecta infraestructura de phishing que ni siquiera es un typosquat obvio.
  - Ambas son opcionales: si las librerías correspondientes no están instaladas, la herramienta avisa y continúa con el análisis DNS básico.

- 🚦 **Clasificación de riesgo automática**:
  - 🔴 **CRÍTICO**: el dominio resuelve IP y tiene registros MX (posible servidor de correo para phishing). Se marca `CRÍTICO (registro reciente)` si además fue registrado hace menos de 30 días.
  - 🟡 **ALTO**: el dominio existe (tiene A o MX) pero no ambos.
  - 🟢 **DISPONIBLE**: el dominio no está registrado (oportunidad de compra defensiva).

- 🖥️ **Interfaz TUI en tiempo real con Rich, optimizada para grandes volúmenes**:
  - Barra de progreso global (`X/N` dominios analizados, tiempo transcurrido).
  - Vista en vivo enfocada en los **hallazgos de riesgo** (CRÍTICO/ALTO) en lugar de repintar cientos de filas por segundo — evita parpadeo y consumo de CPU innecesario con `--max-variants` altos.
  - Panel de contadores en vivo (crítico, alto, disponible, error).
  - Colores según riesgo (rojo, amarillo, verde, cian).

- 📊 **Reporte final y exportación dual (JSON + CSV)**:
  - Resumen con totales, incluyendo dominios recién registrados.
  - Tabla final filtrada a dominios registrados (evita inundar la consola con cientos de "disponibles"); el detalle completo de todas las variantes queda en los archivos exportados.
  - `phish_report.json`: estructura completa lista para integrar en SIEM/SOAR.
  - `phish_report.csv`: mismo detalle en formato tabular para Excel/Sheets.
  - Sección adicional `certificate_transparency_hits` en el JSON cuando se usa `--crtsh`.

- 🛡️ **Código modular y listo para producción**:
  - Clases bien definidas: `TyposquatEngine`, `DNSChecker`, `WhoisChecker`, `CertTransparencyChecker`, `TUIConsole`, `PhishTracker`.
  - CLI con `argparse` (validación de argumentos, ayuda автоgenerada con `-h`).
  - Manejo correcto de TLDs compuestos (`empresa.co.uk`) vía `tldextract`, forzado a usar solo su snapshot local para no depender de red en entornos aislados.
  - Manejo exhaustivo de excepciones.
  - Interrupción limpia con `Ctrl+C` mediante manejador de señales de `asyncio` (cancela tareas pendientes en lugar de dejarlas colgadas).

---

## 📦 Instalación

### Requisitos previos

- Python 3.8 o superior
- pip (gestor de paquetes de Python)

### Clonar el repositorio

```bash
git clone https://github.com/tu-usuario/phish-tracker.git
cd phish-tracker
```

### Crear y activar un entorno virtual (recomendado)

```bash
python3 -m venv venv
source venv/bin/activate   # En Windows: venv\Scripts\activate
```

### Instalar dependencias

```bash
pip install -r requirements.txt
```

El archivo `requirements.txt` incluye dependencias núcleo y opcionales:

```text
# Núcleo (obligatorio)
rich>=13.7.0
dnspython>=2.6.0

# Opcionales — la herramienta funciona sin ellos, mostrando un aviso
tldextract>=5.1.0      # manejo correcto de TLDs compuestos (co.uk, com.ar...)
python-whois>=0.9.4    # habilita --whois (antigüedad de registro)
aiohttp>=3.9.0          # habilita --crtsh (Certificate Transparency)
```

Si solo quieres la funcionalidad básica, puedes instalar únicamente `rich` y `dnspython`; los flags `--whois` y `--crtsh` quedarán deshabilitados con un aviso claro en pantalla.

---

## 🚀 Uso

### Sintaxis básica

```bash
python phishTracker.py <dominio-objetivo> [opciones]
```

### Opciones disponibles

| Opción | Descripción | Valor por defecto |
|---|---|---|
| `domain` | Dominio objetivo (obligatorio, debe incluir TLD, p. ej. `example.com`) | — |
| `--max-variants` | Máximo de variantes a analizar | `1000` |
| `--concurrency` | Consultas DNS concurrentes | `100` |
| `--timeout` | Timeout DNS en segundos | `3.0` |
| `--nameservers` | Nameservers personalizados, separados por coma | resolutor del sistema |
| `--whois` | Verifica antigüedad de registro en dominios encontrados | desactivado |
| `--crtsh` | Busca infraestructura adicional en Certificate Transparency | desactivado |
| `--output` | Prefijo de los archivos de salida (`.json` / `.csv`) | `phish_report` |

Consulta la ayuda completa (generada automáticamente por `argparse`) en cualquier momento con:

```bash
python phishTracker.py -h
```

### Ejemplos

Análisis básico:

```bash
python phishTracker.py example.com
```

Análisis completo con detección de registros recientes e infraestructura adicional:

```bash
python phishTracker.py example.com --whois --crtsh
```

Escaneo más rápido y agresivo, con resolutores propios:

```bash
python phishTracker.py example.com --max-variants 500 --concurrency 200 --nameservers 1.1.1.1,8.8.8.8
```

Guardar el reporte con un nombre personalizado:

```bash
python phishTracker.py example.com --output reportes/example_2026
```

### Salida esperada

```text
        ____  _     _      _     _____               _
       |  _ \| |   (_)    | |   |_   _|             | |
       | |_) | |__  _ ___ | |__   | |_ __ __ _  ___| | _____ _ __
       |  __/| '_ \| / __|| '_ \  | | '__/ _` |/ __| |/ / _ \ '__|
       | |   | | | | \__ \| | | | | | | | (_| | (__|   <  __/ |
       |_|   |_| |_|_|___/|_| |_| |_|_|  \__,_|\___|_|\_\___|_|

╭───────────────────────────────────────────────────────╮
│ PHISH-TRACKER // Threat Intel & Typosquatting Watcher │
│ Objetivo: example.com                                 │
│ Máx. variantes: 1000   Concurrencia: 100   Timeout: 3.0s │
╰───────────────────────────────────────────────────────╯

Generando variaciones...
Se generaron 1000 variaciones (de un espacio combinatorio mayor, priorizadas).

⠋ Escaneando dominios...                              120/1000 0:00:04
╭─────────────────────────────────────────────────────────────────╮
│ Analizadas: 120/1000   Crítico: 1   Alto: 3   Disponible: 114  │
╰─────────────────────────────────────────────────────────────────╯
                Hallazgos de riesgo (en vivo)
[Tabla filtrada mostrando solo CRÍTICO/ALTO...]

Al finalizar, se muestra la tabla de dominios registrados y se generan
phish_report.json y phish_report.csv.
```

---

## 📄 Ejemplo de reporte JSON

```json
{
  "summary": {
    "target_domain": "example.com",
    "total_variants": 1000,
    "registered": 12,
    "critical": 3,
    "high": 9,
    "available": 986,
    "errors": 2,
    "recently_registered": 2
  },
  "certificate_transparency_hits": [
    "example-secure-payments.net"
  ],
  "results": [
    {
      "domain": "exmple.com",
      "technique": "omission",
      "status": "critical",
      "ip": "192.0.2.1",
      "mx_servers": ["mail.exmple.com"],
      "risk_level": "CRÍTICO (registro reciente)",
      "created_date": "2026-08-20 00:00:00",
      "days_since_registration": 16,
      "recently_registered": true,
      "error": null
    },
    {
      "domain": "example-login.com",
      "technique": "keyword",
      "status": "high",
      "ip": "192.0.2.2",
      "mx_servers": [],
      "risk_level": "ALTO",
      "created_date": null,
      "days_since_registration": null,
      "recently_registered": false,
      "error": null
    },
    {
      "domain": "exampel.com",
      "technique": "transposition",
      "status": "available",
      "ip": null,
      "mx_servers": [],
      "risk_level": "DISPONIBLE",
      "created_date": null,
      "days_since_registration": null,
      "recently_registered": false,
      "error": null
    }
  ]
}
```

El archivo `phish_report.csv` contiene las mismas columnas (`domain`, `technique`, `status`, `risk_level`, `ip`, `mx_servers`, `created_date`, `days_since_registration`, `recently_registered`, `error`) en formato tabular, listo para abrir en Excel/Sheets o cargar en un SIEM.

---

## 🧩 Estructura del proyecto

```text
phish-tracker/
├── phishTracker.py          # Código principal
├── requirements.txt         # Dependencias (núcleo + opcionales)
├── README.md                 # Documentación
├── phish_report.json        # Reporte JSON generado (tras ejecución)
└── phish_report.csv         # Reporte CSV generado (tras ejecución)
```

El código está organizado en clases:

| Clase | Responsabilidad |
|---|---|
| `TyposquatEngine` | Genera y prioriza todas las variaciones de dominio (keywords, TLD-swap, homóglifos, transposiciones, omisiones, inserciones). |
| `DNSChecker` | Realiza consultas DNS asíncronas (A y MX) con concurrencia y nameservers configurables. |
| `WhoisChecker` | *(opcional)* Consulta la fecha de registro de los dominios encontrados y marca los recién registrados. |
| `CertTransparencyChecker` | *(opcional)* Busca en crt.sh certificados SSL que mencionen la marca objetivo. |
| `TUIConsole` | Maneja la interfaz Rich: barra de progreso, tabla en vivo filtrada por riesgo, paneles y colores. |
| `PhishTracker` | Orquesta el flujo completo: generación, análisis DNS, enriquecimiento opcional, visualización y exportación. |

---

## 🔍 Casos de uso en Threat Intelligence

- **Monitoreo continuo de marca**: programa ejecuciones periódicas (cron, CI/CD) con `--whois --crtsh` para detectar nuevos dominios sospechosos que imiten tu marca apenas se registren.
- **Investigación de incidentes**: cuando se reporta una campaña de phishing, analiza rápidamente variantes del dominio legítimo para identificar infraestructura relacionada, incluyendo cambios de TLD.
- **Compra defensiva**: identifica dominios disponibles (`DISPONIBLE`) que podrían ser registrados por atacantes y adquiérelos preventivamente.
- **Priorización de respuesta**: usa la señal de "registro reciente" (`--whois`) para distinguir infraestructura de phishing activa de dominios parqueados antiguos con configuraciones DNS incidentales.
- **Enriquecimiento de feeds**: integra el JSON/CSV generado en tu SIEM o plataforma de inteligencia para correlacionar con otros indicadores.

---

## ⚠️ Advertencia ética y legal

Esta herramienta está destinada exclusivamente para:

- Pruebas de seguridad autorizadas.
- Monitoreo defensivo de dominios propios o de marcas para las que tengas permiso explícito.
- Investigación académica o de inteligencia de amenazas.

No debes utilizar Phish-Tracker para analizar dominios de terceros sin autorización, ya que podría violar leyes de privacidad, términos de servicio de registradores o normativas locales. El uso de `--whois` y `--crtsh` implica consultar servicios públicos de terceros (WHOIS, crt.sh); respeta sus límites de uso razonable. El usuario es el único responsable del uso que haga de esta herramienta.

---

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Si deseas mejorar el motor de variaciones, añadir nuevas técnicas de typosquatting (p. ej. bit-squatting, combosquatting) o integrar APIs externas (VirusTotal, PassiveTotal, etc.), por favor abre un issue o envía un pull request.

### Guía rápida

1. Haz un fork del repositorio.
2. Crea una rama con tu feature: `git checkout -b feature/nueva-tecnica`.
3. Realiza tus cambios y haz commit.
4. Envía un pull request.

---

## 📝 Licencia

Distribuido bajo la licencia MIT. Consulta el archivo `LICENSE` para más detalles.

## 🙏 Agradecimientos

- [dnspython](https://www.dnspython.org/) por la resolución DNS asíncrona.
- [Rich](https://github.com/Textualize/rich) por la magnífica interfaz de terminal.
- [tldextract](https://github.com/john-kurkowski/tldextract) por el manejo correcto de TLDs compuestos.
- [python-whois](https://github.com/richardpenman/whois) por las consultas WHOIS.
- [crt.sh](https://crt.sh/) por el acceso público a los logs de Certificate Transparency.

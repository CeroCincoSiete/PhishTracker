# Phish-Tracker // Threat Intel & Typosquatting Watcher

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

**Phish-Tracker** es una herramienta de línea de comandos orientada a la **inteligencia de amenazas** y al **monitoreo defensivo de marcas**. Permite detectar dominios *typosquatted* y posibles infraestructuras de phishing que suplantan un dominio objetivo, analizando cientos de variaciones en tiempo real y clasificándolas según su nivel de riesgo.

---

## 🧠 ¿Qué es el Typosquatting?

El *typosquatting* (o suplantación por errores tipográficos) es una técnica utilizada por actores maliciosos para registrar dominios con nombres similares a marcas legítimas, aprovechando errores comunes de escritura, homóglifos o adición de palabras como `login`, `secure`, etc. Estos dominios se emplean en campañas de phishing, distribución de malware o robo de credenciales.

**Phish-Tracker** automatiza la generación de estas variaciones y verifica si están registradas y si poseen registros DNS que indiquen actividad maliciosa.

---

## ✨ Características principales

- ⚡ **Motor de variaciones avanzado**:
  - Omisión de caracteres (`gogle.com` → `gogle.com`).
  - Inserción de caracteres (`google.com` → `googgle.com`).
  - Transposición de letras adyacentes (`google.com` → `gogole.com`).
  - Sustitución por homóglifos (`google.com` → `g00gle.com`).
  - Adición de palabras clave de phishing (`google-login.com`, `verify-google.com`).

- 🌐 **Análisis DNS asíncrono**:
  - Consulta registros **A** (resolución de IP) y **MX** (servidores de correo) usando `asyncio` y `dnspython`.
  - Concurrencia configurable (por defecto 100 consultas simultáneas).
  - Timeout y manejo robusto de errores por dominio.

- 🚦 **Clasificación de riesgo automática**:
  - 🔴 **CRÍTICO**: el dominio resuelve IP y tiene registros MX (posible servidor de correo para phishing).
  - 🟡 **ALTO**: el dominio existe (tiene A o MX) pero no ambos.
  - 🟢 **DISPONIBLE**: el dominio no está registrado (oportunidad de compra defensiva).

- 🖥️ **Interfaz TUI en tiempo real con Rich**:
  - Tabla dinámica que muestra el estado de cada variante mientras se analiza.
  - Colores según riesgo (rojo, amarillo, verde).
  - Actualización en vivo sin bloquear la ejecución.

- 📊 **Reporte final y exportación JSON**:
  - Resumen con totales y porcentajes.
  - Detalle completo de cada dominio, IP, MX y riesgo.
  - Archivo `phish_report.json` listo para integrar en otros sistemas (SIEM, SOAR, etc.).

- 🛡️ **Código modular y listo para producción**:
  - Clases bien definidas: `TyposquatEngine`, `DNSChecker`, `TUIConsole`.
  - Manejo exhaustivo de excepciones.
  - Interrupción limpia con `Ctrl+C`.

---

## 📦 Instalación

### Requisitos previos

- Python 3.8 o superior
- pip (gestor de paquetes de Python)

### Clonar el repositorio

```bash
git clone https://github.com/tu-usuario/phish-tracker.git
cd phish-tracker

Crear y activar un entorno virtual (recomendado)
bash

python3 -m venv venv
source venv/bin/activate   # En Windows: venv\Scripts\activate
```
### Instalar dependencias
```bash

pip install -r requirements.txt

El archivo requirements.txt incluye:
text

dnspython>=2.0
rich>=13.0
```
## 🚀 Uso

Sintaxis básica
```bash

python pishTracker.py <dominio-objetivo> [max_variantes]

    <dominio-objetivo>: dominio a analizar (obligatorio, debe incluir TLD, p. ej. example.com).

    [max_variantes]: número máximo de variantes a generar (opcional, por defecto 1000).
```
## Ejemplo
```bash

python pishTracker.py example.com
```
### Salida esperada:
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
╰───────────────────────────────────────────────────────╯

Generando variaciones...
Se generaron 432 variaciones.

[Tabla en vivo con los resultados...]

Al finalizar, se mostrará una tabla final y se generará el archivo phish_report.json.
```
### 📄 Ejemplo de reporte JSON
```json

{
  "summary": {
    "target_domain": "example.com",
    "total_variants": 432,
    "registered": 12,
    "critical": 3,
    "available": 410,
    "errors": 2
  },
  "results": [
    {
      "domain": "exmple.com",
      "status": "critical",
      "ip": "192.0.2.1",
      "mx_servers": ["mail.exmple.com"],
      "risk_level": "CRÍTICO",
      "error": null
    },
    {
      "domain": "example-login.com",
      "status": "high",
      "ip": "192.0.2.2",
      "mx_servers": [],
      "risk_level": "ALTO",
      "error": null
    },
    {
      "domain": "exampel.com",
      "status": "available",
      "ip": null,
      "mx_servers": [],
      "risk_level": "DISPONIBLE",
      "error": null
    }
  ]
}
```
## 🧩 Estructura del proyecto
```text

phish-tracker/
├── pishTracker.py          # Código principal
├── requirements.txt        # Dependencias
├── README.md               # Documentación
└── phish_report.json       # Reporte generado (tras ejecución)
```
El código está organizado en clases:

  Clase	Responsabilidad

    TyposquatEngine	Genera todas las variaciones de dominio según técnicas configuradas.
    DNSChecker	Realiza consultas DNS asíncronas (A y MX) con concurrencia limitada.
    TUIConsole	Maneja la interfaz Rich (tablas en vivo, paneles, colores).
    PhishTracker	Orquesta el flujo completo: generación, análisis, visualización y exportación.

### 🔍 Casos de uso en Threat Intelligence

    Monitoreo continuo de marca: programa ejecuciones periódicas (cron, CI/CD) para detectar nuevos dominios sospechosos que imiten tu marca.

    Investigación de incidentes: cuando se reporta una campaña de phishing, analiza rápidamente variantes del dominio legítimo para identificar infraestructura relacionada.

    Compra defensiva: identifica dominios disponibles que podrían ser registrados por atacantes y adquiérelos preventivamente.

    Enriquecimiento de feeds: integra el JSON generado en tu SIEM o plataforma de inteligencia para correlacionar con otros indicadores.

### ⚠️ Advertencia ética y legal

Esta herramienta está destinada exclusivamente para:

    Pruebas de seguridad autorizadas.

    Monitoreo defensivo de dominios propios o de marcas para las que tengas permiso explícito.

    Investigación académica o de inteligencia de amenazas.

No debes utilizar Phish-Tracker para analizar dominios de terceros sin autorización, ya que podría violar leyes de privacidad, términos de servicio de registradores o normativas locales. El usuario es el único responsable del uso que haga de esta herramienta.
🤝 Contribuciones

Las contribuciones son bienvenidas. Si deseas mejorar el motor de variaciones, añadir nuevas técnicas de typosquatting o integrar APIs externas (VirusTotal, PassiveTotal, etc.), por favor abre un issue o envía un pull request.
Guía rápida

    Haz un fork del repositorio.

    Crea una rama con tu feature: git checkout -b feature/nueva-tecnica.

    Realiza tus cambios y haz commit.

    Envía un pull request.

### 📝 Licencia

Distribuido bajo la licencia MIT. Consulta el archivo LICENSE para más detalles.
🙏 Agradecimientos

    dnspython por la resolución DNS asíncrona.

    Rich por la magnífica interfaz de terminal.

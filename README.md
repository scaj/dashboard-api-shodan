# Dashboard-api-shodan
Herramienta de auditoría de seguridad IoT con backend en FastAPI y frontend en React, integrando Shodan, NVD y Vulners.

Este repositorio ha sido desarrollado para analizar la exposición y los riesgos de seguridad asociados a dispositivos y servicios IoT accesibles desde Internet, utilizando la API de Shodan y técnicas de análisis pasivo y activo.

El trabajo se centra en la observación, análisis e interpretación de la información obtenida a partir de servicios expuestos, banners y metadatos, así como en la identificación de posibles vulnerabilidades, siempre desde un enfoque ético y responsable.


## Descripción del proyecto

La arquitectura del proyecto se compone de:

- **Scripts en Python** desarrollados específicamente para:
  - Interactuar con la API de Shodan.
  - Analizar servicios expuestos y banners.
  - Correlacionar resultados con bases de datos de vulnerabilidades (NVD y Vulners).
  - Complementar los resultados mediante escaneos activos con Nmap.

- **Backend en FastAPI**, encargado de:
  - Ejecutar los scripts de forma dinámica.
  - Centralizar la lógica del análisis.
  - Gestionar y exponer los resultados obtenidos.

- **Frontend en React**, que permite:
  - Lanzar las pruebas de forma sencilla.
  - Visualizar los resultados de manera estructurada y accesible.
  - Facilitar la comparación entre distintas herramientas y ejecuciones.

Los resultados de los análisis se almacenan en **archivos JSON estructurados**, lo que permite su análisis posterior, la reproducibilidad de los experimentos y la comparación entre distintas ejecuciones.



## Tecnologías utilizadas

- Python 3
- FastAPI
- Shodan API
- NVD API
- Vulners API
- Nmap
- React
- Docker y Docker Compose


## 📁 Estructura del repositorio

├── backend/

│ ├── app/

│ │ ├── main.py

│ │ ├── routers/

│ │ ├── services/

│ │ └── scripts/

│ ├── requirements.txt

│ └── Dockerfile

│

├── frontend/

│ ├── src/

│ ├── package.json

│ └── README.md

│

├── docker-compose.yml

├── .env.example

├── README.md

└── LICENSE


## Instalación y ejecución

1. Clona este repositorio:
   ```bash
   git clone https://github.com/tu-usuario/dashboard-api-shodan.git
   cd dashboard-api-shodan


## Levanta los servicios con Docker Compose:

    docker-compose up --build

## Accede al frontend en:

    http://localhost:3000

## Y al backend en:

    http://localhost:8000


## Uso de los scripts

  - Los scripts en backend/app/scripts/ pueden ejecutarse directamente desde FastAPI o de manera manual para pruebas puntuales.

  - Los resultados se generan en JSON, con campos como: IP, puerto, servicio, banner, CVE, CVSS, geolocalización.

  - Ejemplo de ejecución manual:

      python backend/app/scripts/active_scan.py --ip 1.2.3.4


  - Para Nmap, el script nmap_scan.py permite ejecutar escaneos activos y exportar resultados en JSON:

      python backend/app/scripts/nmap_scan.py --ip 1.2.3.4



## Recomendaciones y buenas prácticas

  - No realizar pruebas sobre sistemas de terceros sin autorización.

  - Mantener las claves de API seguras y nunca subirlas al repositorio.

  - Ejecutar las pruebas en entornos controlados o con IPs propias.

  - Revisar periódicamente los servicios expuestos y aplicar actualizaciones.

  - Aplicar autenticación robusta, VPNs o proxies inversos para reducir la exposición de servicios críticos.

  - Guardar y documentar todos los resultados para reproducibilidad y seguimiento académico.

## Resultados y reproducibilidad

  - Todos los datos de salida se almacenan en JSON, permitiendo reproducir los experimentos y comparar resultados.

  - Se incluyen ejemplos de JSON de resultados en examples/ (si decides añadir esta carpeta).

  - Permite validar la exposición de servicios, banners, versiones de software y vulnerabilidades de manera ética y controlada.

## Licencia

Este proyecto se distribuye bajo MIT License, permitiendo el uso académico y personal.

    

# takeovflow

Subdomain Takeover Scanner en Python  
Versión avanzada de la herramienta desarrollada por TheOffSecGirl.

---

## 1. Descripción

`takeovflow` es un escáner para detectar posibles **subdomain takeovers** en uno o varios dominios.

Orquesta varias herramientas externas:

- Descubrimiento de subdominios: `subfinder`, `assetfinder`
- Resolución y filtrado: `dnsx`, `httpx`, `dig`, `jq`, `curl`
- Detección de posibles takeovers: `subjack`, `nuclei`
- Generación de un **informe final en Markdown** con el resumen del análisis

Está pensado para entornos de **bug bounty**, **hacking ético** y auditorías ofensivas.

---

## 2. Requisitos

Sistema recomendado:

- Linux (probado)  
- macOS debería funcionar si todas las herramientas están correctamente instaladas y en el `PATH`.

Dependencias externas necesarias:

- subfinder
- assetfinder
- subjack
- httpx
- dnsx
- nuclei
- dig
- jq
- curl
- Python 3 (≥ 3.7)

---

## 3. Instalación

```bash
git clone https://github.com/theoffsecgirl/takeovflow.git
cd takeovflow
chmod +x takeovflow.py
```

---

## 4. Uso rápido

```bash
python3 takeovflow.py -d example.com -v
```

```bash
python3 takeovflow.py -f dominios.txt
```

```bash
python3 takeovflow.py -l "dominio1.com,dominio2.net"
```

---

## 5. Opciones disponibles

```text
-d, --domain   Escanear un único dominio
-f, --file     Archivo con lista de dominios (uno por línea)
-l, --list     Lista de dominios separados por comas
-t, --threads  Número de hilos (50 por defecto)
-r, --rate     Rate limit (2 por defecto)
-v, --verbose  Modo verbose
-h, --help     Ayuda
```

---

## 6. Flujo interno

1. Normaliza y valida dominios.  
2. Descubre subdominios (subfinder, assetfinder).  
3. Resuelve y filtra (dnsx, httpx, dig, jq).  
4. Busca takeovers (subjack, nuclei).  
5. Combina y deduplica resultados.  
6. Genera informe final en Markdown.

---

## 7. Archivos generados

- Directorio temporal `takeovflow_tmp_*`
- Archivos intermedios (`*_subfinder.txt`, `*_assetfinder.txt`)
- `potential_takeovers_*`
- `dns_analysis.txt`
- `takeover_analysis.txt`
- Informe final: `subdomain_takeover_report_YYYYMMDD.md`

---

## 8. Buenas prácticas

- Respeta siempre el marco legal.  
- No escanees sin permiso.  
- Ajusta threads y rate limits.  
- Usa repos privados para informes sensibles.

---

## 9. Limitaciones

- Depende de herramientas externas.  
- La detección no es infalible.  
- Resultados ligados a versiones de herramientas.

---

## 10. Contribuciones

Pull requests bienvenidos.  
Reporta issues para mejoras y bugs.

---

## 11. Licencia

Uso ético únicamente. Sin garantías.

---

## 12. Autor

TheOffSecGirl  
GitHub: https://github.com/theoffsecgirl

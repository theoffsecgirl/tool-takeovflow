# takeovflow

Subdomain Takeover Scanner avanzado escrito en Python  
Versión mejorada por **TheOffSecGirl**

---

## 1. Descripción

`takeovflow` es un escáner ofensivo diseñado para detectar posibles **subdomain takeovers** combinando descubrimiento pasivo, resolución activa, detección con subjack/nuclei y análisis de patrones de CNAME asociados a servicios susceptibles de takeover.

Incluye:

- Descubrimiento pasivo (subfinder, assetfinder)
- Resolución DNS (dnsx)
- Fingerprints de takeover (subjack)
- Templates de takeover (nuclei)
- Detección de patrones de CNAME sospechosos
- Informe automático en Markdown
- (Opcional) Informe JSON para pipelines o integraciones

---

## 2. Requisitos

Herramientas externas necesarias:

- subfinder
- assetfinder
- dnsx
- httpx
- subjack
- nuclei
- dig
- jq
- curl
- Python 3.7+

El script comprueba automáticamente su disponibilidad.

---

## 3. Instalación

```bash
git clone https://github.com/theoffsecgirl/tool-takeovflow.git
cd tool-takeovflow
chmod +x takeovflow.py
```

---

## 4. Uso rápido

### Dominio único

```bash
python3 takeovflow.py -d example.com -v
```

### Archivo con dominios

```bash
python3 takeovflow.py -f scope.txt
```

### Lista separada por comas

```bash
python3 takeovflow.py -l "dom1.com,dom2.net"
```

---

## 5. Modos nuevos

### Solo pasivo

```bash
python3 takeovflow.py -d example.com --passive-only
```

### Solo activo

```bash
python3 takeovflow.py -d example.com --active-only
```

### Informe JSON

```bash
python3 takeovflow.py -d example.com --json-output
```

### Templates personalizados de nuclei

```bash
python3 takeovflow.py -d example.com --nuclei-templates ./mis-templates/
```

---

## 6. Flujo técnico

### Fase pasiva
- subfinder  
- assetfinder  
- deduplicación  
- `*_subdomains_all.txt`

### Fase activa
- dnsx resolución  
- httpx servicios web  
- subjack detección de takeovers  
- nuclei checks adicionales  
- CNAME sospechosos:
  - AWS S3
  - CloudFront
  - GitHub Pages
  - Heroku
  - Azure
  - Fastly
  - más servicios conocidos

### Output
- Informe Markdown
- Informe JSON (opcional)
- Directorio temporal con todos los resultados

---

## 7. Ejemplo completo

```bash
python3 takeovflow.py -f scope.txt -t 100 -r 5 -v --json-output     --nuclei-templates ./takeover-templates/
```

---

## 8. Archivos generados

- `takeovflow_tmp_*`
- `*_subfinder.txt`
- `*_assetfinder.txt`
- `*_subdomains_all.txt`
- `*_dnsx.txt`
- `*_httpx.txt`
- `*_subjack.txt`
- `*_nuclei.txt`
- `*_cname_patterns.txt`
- `subdomain_takeover_report_YYYYMMDD.md`
- `subdomain_takeover_report_YYYYMMDD.json` (si se activa)

---

## 9. Limitaciones

- Depende de herramientas externas.
- Posibles falsos positivos/negativos.
- CNAME heurístico: verificar manualmente.

---

## 10. Licencia

Uso ético y responsable únicamente. Sin garantías.

---

## 11. Autora

**TheOffSecGirl**  
https://github.com/theoffsecgirl

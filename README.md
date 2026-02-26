<div align="center">

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- BANNER SVG WAVE -->
<!-- ═══════════════════════════════════════════════════════════ -->
<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0:0b1220,50:10B981,100:0b1220&height=220&section=header&text=&fontSize=1" />

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- ANIMATED TITLE -->
<!-- ═══════════════════════════════════════════════════════════ -->
<img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&weight=900&size=65&duration=3000&pause=1000&color=10B981&center=true&vCenter=true&width=600&height=90&lines=%F0%9F%94%8D+LogLens" alt="LogLens" />

<br>

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- TAGLINE -->
<!-- ═══════════════════════════════════════════════════════════ -->
<img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&weight=400&size=18&duration=4000&pause=2000&color=9CA3AF&center=true&vCenter=true&width=980&height=30&lines=Plateforme+l%C3%A9g%C3%A8re+de+monitoring+et+d'analyse+de+logs+en+temps+r%C3%A9el;Ingestion+multi-format+%7C+D%C3%A9tection+automatique+%7C+Alertes+%7C+Dashboard;~550+lignes+de+code.+Z%C3%A9ro+config.+Z%C3%A9ro+d%C3%A9pendance+externe." alt="tagline" />

<br><br>

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- TECH BADGES -->
<!-- ═══════════════════════════════════════════════════════════ -->
<a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" /></a>
<a href="https://fastapi.tiangolo.com"><img src="https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" /></a>
<a href="https://sqlite.org"><img src="https://img.shields.io/badge/SQLite-WAL-003B57?style=for-the-badge&logo=sqlite&logoColor=white" /></a>
<a href="https://developer.mozilla.org"><img src="https://img.shields.io/badge/Vanilla_JS-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black" /></a>
<a href="https://www.chartjs.org"><img src="https://img.shields.io/badge/Chart.js-FF6384?style=for-the-badge&logo=chartdotjs&logoColor=white" /></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-10B981?style=for-the-badge" /></a>

<br><br>

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- STATS BADGES -->
<!-- ═══════════════════════════════════════════════════════════ -->
<img src="https://img.shields.io/badge/📦_Fichiers-5-0b1220?style=flat-square&labelColor=1f2937" />
&nbsp;
<img src="https://img.shields.io/badge/📏_Lignes-~550-0b1220?style=flat-square&labelColor=1f2937" />
&nbsp;
<img src="https://img.shields.io/badge/⚙️_Config-Zéro-10B981?style=flat-square&labelColor=1f2937" />
&nbsp;
<img src="https://img.shields.io/badge/🗄️_Dépendances_externes-Zéro-10B981?style=flat-square&labelColor=1f2937" />
&nbsp;
<img src="https://img.shields.io/badge/🚀_Démarrage-1_commande-10B981?style=flat-square&labelColor=1f2937" />

<br><br>

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- SCREENSHOT -->
<!-- ═══════════════════════════════════════════════════════════ -->
<img src="screenshot.PNG" alt="LogLens Dashboard" width="900" />

<br>

<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0:0b1220,50:10B981,100:0b1220&height=120&section=footer" />

</div>

<!-- ═══════════════════════════════════════════════════════════ -->
<!--                     FONCTIONNALITES                       -->
<!-- ═══════════════════════════════════════════════════════════ -->

<h2>
  <img src="https://img.shields.io/badge/🎯-Fonctionnalités-10B981?style=for-the-badge&labelColor=0b1220" />
</h2>

<!-- ────────────────────────────────────────────────────────── -->

<h3>📥 Ingestion multi-format avec détection automatique</h3>

<p>LogLens détecte et parse automatiquement les formats suivants <b>sans aucune configuration</b> :</p>

<table>
  <thead>
    <tr>
      <th>Format</th>
      <th>Exemple</th>
      <th>Extraction</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><b>JSON / JSONL</b></td>
      <td><code>{"level":"ERROR","message":"timeout","duration":3.5}</code></td>
      <td>Champs numériques + string</td>
    </tr>
    <tr>
      <td><b>Syslog</b></td>
      <td><code>Feb 26 14:30:01 srv01 nginx[1234]: request failed</code></td>
      <td>Host, process, PID, message</td>
    </tr>
    <tr>
      <td><b>Nginx access log</b></td>
      <td><code>192.168.1.1 - - [26/Feb/2026:14:30:01] "GET /api" 200 1234</code></td>
      <td>IP, method, path, status, bytes, response_time</td>
    </tr>
    <tr>
      <td><b>CSV / TSV</b></td>
      <td>Détection automatique du séparateur via <code>csv.Sniffer</code></td>
      <td>Toutes les colonnes</td>
    </tr>
    <tr>
      <td><b>Plain text</b></td>
      <td>Tout le reste</td>
      <td>Timestamps ISO, nombres, level</td>
    </tr>
  </tbody>
</table>

<br>

<blockquote>
  ✅ <b>Timestamp</b> normalisé (8 formats supportés)<br>
  ✅ <b>Level</b> déduit par analyse du contenu (ERROR, WARN, INFO, DEBUG)<br>
  ✅ <b>Métriques numériques</b> extraites et indexées<br>
  ✅ <b>Catégories string</b> extraites et comptabilisées
</blockquote>

<!-- ────────────────────────────────────────────────────────── -->

<h3>🚨 Système d'alertes</h3>

<blockquote>
  🔔 Règles configurables : métrique + condition (<code>gt</code>, <code>lt</code>, <code>eq</code>) + seuil + fenêtre temporelle<br>
  ⏱️ Boucle de vérification toutes les 30 secondes<br>
  🔗 Notifications par <b>webhook</b> (JSON POST) et/ou <b>email</b> (SMTP)<br>
  📜 Historique des alertes déclenchées
</blockquote>

<!-- ────────────────────────────────────────────────────────── -->

<h3>📊 Dashboard temps réel</h3>

<blockquote>
  📈 <b>Line charts</b> pour chaque métrique numérique par source<br>
  🥧 <b>Pie charts</b> pour la distribution des catégories<br>
  🖥️ <b>Log viewer</b> coloré par level — <code>ERROR</code> 🔴 <code>WARN</code> 🟠 <code>INFO</code> 🟢 <code>DEBUG</code> ⚪<br>
  📋 <b>Stats globales</b> : ingestion/min, sources actives, alertes actives<br>
  🔄 Rafraîchissement automatique toutes les 10 secondes<br>
  🕐 Sélecteur de plage : 5min · 15min · 1h · 6h · 24h
</blockquote>

<!-- ────────────────────────────────────────────────────────── -->

<h3>🔌 API REST</h3>

<table>
  <thead>
    <tr>
      <th>Méthode</th>
      <th>Endpoint</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><img src="https://img.shields.io/badge/POST-49cc90?style=flat-square" /></td>
      <td><code>/api/ingest?source=nom</code></td>
      <td>Ingestion de logs (JSON, texte, CSV)</td>
    </tr>
    <tr>
      <td><img src="https://img.shields.io/badge/GET-61affe?style=flat-square" /></td>
      <td><code>/api/sources</code></td>
      <td>Liste des sources détectées</td>
    </tr>
    <tr>
      <td><img src="https://img.shields.io/badge/GET-61affe?style=flat-square" /></td>
      <td><code>/api/metrics?source=X&amp;from=T1&amp;to=T2</code></td>
      <td>Séries temporelles des métriques</td>
    </tr>
    <tr>
      <td><img src="https://img.shields.io/badge/GET-61affe?style=flat-square" /></td>
      <td><code>/api/categories?source=X</code></td>
      <td>Distribution des catégories</td>
    </tr>
    <tr>
      <td><img src="https://img.shields.io/badge/GET-61affe?style=flat-square" /></td>
      <td><code>/api/logs?source=X&amp;level=ERROR&amp;limit=100</code></td>
      <td>Consultation des logs</td>
    </tr>
    <tr>
      <td><img src="https://img.shields.io/badge/GET-61affe?style=flat-square" /></td>
      <td><code>/api/stats</code></td>
      <td>Statistiques globales</td>
    </tr>
    <tr>
      <td><img src="https://img.shields.io/badge/POST-49cc90?style=flat-square" /></td>
      <td><code>/api/alerts/rules</code></td>
      <td>Création d'une règle d'alerte</td>
    </tr>
    <tr>
      <td><img src="https://img.shields.io/badge/DELETE-f93e3e?style=flat-square" /></td>
      <td><code>/api/alerts/rules/{id}</code></td>
      <td>Suppression d'une règle</td>
    </tr>
    <tr>
      <td><img src="https://img.shields.io/badge/GET-61affe?style=flat-square" /></td>
      <td><code>/api/alerts</code></td>
      <td>Règles et historique des alertes</td>
    </tr>
  </tbody>
</table>

<br>

<!-- ═══════════════════════════════════════════════════════════ -->
<!--                      INSTALLATION                         -->
<!-- ═══════════════════════════════════════════════════════════ -->

<h2>
  <img src="https://img.shields.io/badge/⚡-Installation-10B981?style=for-the-badge&labelColor=0b1220" />
</h2>

```bash
pip install fastapi uvicorn
```

<br>

<!-- ═══════════════════════════════════════════════════════════ -->
<!--                       LANCEMENT                           -->
<!-- ═══════════════════════════════════════════════════════════ -->

<h2>
  <img src="https://img.shields.io/badge/🚀-Lancement-10B981?style=for-the-badge&labelColor=0b1220" />
</h2>

```bash
python main.py
```

```
 _                _
| |    ___   __ _| |    ___ _ __  ___
| |   / _ \ / _` | |   / _ \ '_ \/ __|
| |__| (_) | (_| | |__|  __/ | | \__ \
|_____\___/ \__, |_____\___|_| |_|___/
            |___/

LogLens running at http://localhost:8000
```

<blockquote>
  💾 La base SQLite <code>loglens.db</code> est créée automatiquement au premier lancement.
</blockquote>

<br>

<!-- ═══════════════════════════════════════════════════════════ -->
<!--                      UTILISATION                          -->
<!-- ═══════════════════════════════════════════════════════════ -->

<h2>
  <img src="https://img.shields.io/badge/📡-Utilisation-10B981?style=for-the-badge&labelColor=0b1220" />
</h2>

<details>
<summary><b>📤 Envoyer des logs JSON</b></summary>
<br>

```bash
curl -X POST http://localhost:8000/api/ingest?source=mon-app \
  -H "Content-Type: application/json" \
  -d '{"level":"ERROR","message":"Connection timeout","duration_ms":3500}'
```

</details>

<details>
<summary><b>📄 Envoyer des logs texte (syslog, nginx, plain)</b></summary>
<br>

```bash
cat /var/log/nginx/access.log | curl -X POST http://localhost:8000/api/ingest?source=nginx \
  -H "Content-Type: text/plain" --data-binary @-
```

</details>

<details>
<summary><b>📊 Envoyer du CSV</b></summary>
<br>

```bash
curl -X POST http://localhost:8000/api/ingest?source=metrics \
  -H "Content-Type: text/plain" \
  -d 'timestamp,level,message,response_time
2026-02-26T14:00:00,INFO,request ok,120
2026-02-26T14:00:01,ERROR,timeout,3500'
```

</details>

<details>
<summary><b>🚨 Créer une alerte</b></summary>
<br>

```bash
curl -X POST http://localhost:8000/api/alerts/rules \
  -H "Content-Type: application/json" \
  -d '{
    "metric_name": "response_time",
    "condition": "gt",
    "threshold": 2000,
    "window_seconds": 60,
    "webhook_url": "https://hooks.slack.com/services/xxx"
  }'
```

</details>

<br>

<!-- ═══════════════════════════════════════════════════════════ -->
<!--                     ARCHITECTURE                          -->
<!-- ═══════════════════════════════════════════════════════════ -->

<h2>
  <img src="https://img.shields.io/badge/🏗️-Architecture-10B981?style=for-the-badge&labelColor=0b1220" />
</h2>

```
LogLens (5 fichiers, ~550 lignes)
│
├── main.py          # FastAPI app, API REST, SQLite, boucle d'alertes
├── detector.py      # Détection de format et parsing multi-format
├── extractor.py     # Extraction de métriques et catégories
├── alerts.py        # Moteur d'alertes, webhooks, email
└── static/
    └── index.html   # Dashboard (vanilla JS + Chart.js)
```

<details>
<summary><b>🗄️ Schéma de la base de données</b></summary>
<br>

```
log_entries          metrics              categories          alert_rules         alert_history
├── id               ├── id               ├── id              ├── id              ├── id
├── timestamp        ├── log_entry_id     ├── log_entry_id    ├── metric_name     ├── rule_id
├── source           ├── metric_name      ├── category_name   ├── condition       ├── triggered_at
├── level            ├── metric_value     ├── category_value  ├── threshold       ├── metric_value
├── message          └── timestamp        └── timestamp       ├── window_seconds  └── notified
├── raw_line                                                  ├── webhook_url
├── format_detected                                           ├── email
└── created_at                                                └── enabled
```

</details>

<br>

<!-- ═══════════════════════════════════════════════════════════ -->
<!--                PRINCIPES DE CONCEPTION                    -->
<!-- ═══════════════════════════════════════════════════════════ -->

<h2>
  <img src="https://img.shields.io/badge/🧠-Principes_de_conception-10B981?style=for-the-badge&labelColor=0b1220" />
</h2>

<table>
  <tr>
    <td align="center" width="25%">
      <img src="https://img.shields.io/badge/⚙️-Zéro_config-10B981?style=for-the-badge&labelColor=1f2937" /><br><br>
      Envoie des logs,<br>LogLens détecte le format
    </td>
    <td align="center" width="25%">
      <img src="https://img.shields.io/badge/📦-Zéro_dépendance-10B981?style=for-the-badge&labelColor=1f2937" /><br><br>
      SQLite embarqué<br>Pas de Redis, Kafka, Elastic
    </td>
    <td align="center" width="25%">
      <img src="https://img.shields.io/badge/🔒-Thread--safe-10B981?style=for-the-badge&labelColor=1f2937" /><br><br>
      DB_LOCK sur toutes les ops<br>WAL mode pour la concurrence
    </td>
    <td align="center" width="25%">
      <img src="https://img.shields.io/badge/🚀-Autonome-10B981?style=for-the-badge&labelColor=1f2937" /><br><br>
      Un seul <code>python main.py</code><br>et c'est en prod
    </td>
  </tr>
</table>

<br>

<!-- ═══════════════════════════════════════════════════════════ -->
<!--                        FOOTER                             -->
<!-- ═══════════════════════════════════════════════════════════ -->

<div align="center">

<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0:0b1220,50:10B981,100:0b1220&height=120&section=footer" />

<br>

<a href="https://github.com/julienmerconsulting"><img src="https://img.shields.io/badge/JMerConsulting-181717?style=for-the-badge&logo=github&logoColor=white" /></a>
&nbsp;
<a href="https://www.linkedin.com/in/julienmer/"><img src="https://img.shields.io/badge/Julien_Mer-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white" /></a>

<br><br>

<img src="https://img.shields.io/badge/Made_with-☕_et_du_code_à_23h-1f2937?style=flat-square" />

</div>

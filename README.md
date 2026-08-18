# Rupux

**Rupux** is a single-platform cybersecurity toolkit — one desktop application
that brings together a live threat dashboard, a guided attack navigator, and a
growing collection of security tools, all under one comfortable GUI.

Built with **Python + PyQt6**, using a plugin-based architecture: every tool is
a self-contained module that plugs into a shared event bus, so the dashboard
and recommendations update live as tools are used — no manual wiring per tool.

---

## ✨ Modules

| Section | Description |
|---|---|
| 🏠 **Live Dashboard** | Real-time risk score, activity feed, and status for the current session |
| 🧭 **Attack Navigator** | Rule-based guidance panel inside the dashboard — suggests what to check next based on live findings |
| 🧰 **Aid Box** | File Type Identifier, Network Device Scanner, Password Policy Analyzer, Network Packet Analyzer |
| 🕵️ **Hacks** | Cryptanalysis, DoS Attack Detector, Secure File Share System, IDS System, Web-App Vulnerability Scan |
| 🚧 **Real Zone** | Reserved section — currently in development |

**Currently implemented:** `File Type Identifier` (Aid Box). All other tools
are scaffolded as placeholders with the full plugin interface ready — see
[`docs/ADDING_A_TOOL.md`](docs/ADDING_A_TOOL.md) to build them out.

---

## 🏗 Architecture

```
Rupux/
├── core/          # engine: event bus, plugin loader, logger, task manager
├── dashboard/      # Live Dashboard + Attack Navigator (not a plugin — always on)
├── modules/
│   ├── aid_box/    # tool plugins
│   ├── hacks/      # tool plugins
│   └── real_zone/  # placeholder
├── gui/            # main window, sidebar, theme
├── main.py
└── requirements.txt
```

Every tool publishes `SecurityEvent`s onto a shared **event bus**. The Live
Dashboard and Attack Navigator subscribe to that bus — so any new tool you
add automatically shows up in the live feed and can trigger recommendations,
without touching dashboard code.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design.

---

## 🚀 Getting Started

```bash
git clone https://github.com/<your-username>/Rupux.git
cd Rupux
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

---

## 🧩 Adding a New Tool

Rupux uses a plugin pattern — dropping a new folder under `modules/aid_box/`
or `modules/hacks/` with a `plugin.py` is enough for it to appear in the
sidebar automatically. See [`docs/ADDING_A_TOOL.md`](docs/ADDING_A_TOOL.md).

---

## 🗺 Roadmap

- [x] Core engine (event bus, plugin loader, task manager, logging)
- [x] Live Dashboard + Attack Navigator
- [x] File Type Identifier
- [ ] Network Device Scanner
- [ ] Password Policy Analyzer
- [ ] Network Packet Analyzer
- [ ] Cryptanalysis
- [ ] DoS Attack Detector
- [ ] Secure File Share System
- [ ] IDS System
- [ ] Web-App Vulnerability Scan
- [ ] Real Zone

---

## ⚠ Disclaimer

Rupux is built for educational and authorized security-testing purposes only.
Only use its tools (network scanning, vulnerability scanning, packet capture,
etc.) on systems and networks you own or have explicit permission to test.

## License

MIT — see `LICENSE`.

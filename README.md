

# BC's Browser

<img src="./assets/web-ui.png" alt="BC's Browser Web UI" width="full"/>

<br/>

[![GitHub stars](https://img.shields.io/github/stars/breakingcircuits1337/bcs-browser?style=social)](https://github.com/breakingcircuits1337/bcs-browser/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Documentation](https://img.shields.io/badge/Documentation-📕-blue)](https://breakingcircuits.com)

**BC's Browser** is a cutting-edge tool **created by [Breaking Circuits](https://breakingcircuits.com)** that allows Large Language Models (LLMs) to control a browser, enabling seamless interaction with web-based applications and services. Built on top of the [browser-use](https://github.com/browser-use/browser-use) framework, this project is tailored for tech enthusiasts and developers who want to explore the potential of AI-driven browser automation.

---

## Key Features

- **AI-Driven Browser Control**: Enables LLMs to interact with and control a browser, automating tasks and workflows.
- **Expanded LLM Support**: Supports integration with various LLMs, including Google, OpenAI, Azure OpenAI, Anthropic, DeepSeek, Ollama, and more.
- **Custom Browser Support**: Use your own browser instance, eliminating the need to re-login or reconfigure authentication.
- **Persistent Browser Sessions**: Keep the browser window open between tasks to maintain state and history.
- **High-Definition Screen Recording**: Capture browser interactions in high quality for analysis or debugging.
- **User-Friendly WebUI**: Built on Gradio, the WebUI provides an intuitive interface for managing and interacting with the browser agent.

---

## Why BC's Browser?

At **[Breaking Circuits](https://breakingcircuits.com)**, we’re passionate about pushing the boundaries of AI and automation. **BC's Browser** is our latest innovation, designed to empower developers and tech enthusiasts to harness the full potential of LLMs in browser automation. Whether you're building AI agents, testing web applications, or exploring new ways to interact with the web, **BC's Browser** is here to make it easier and more efficient.

---

## Installation Guide

### Prerequisites
- Python 3.11 or higher
- Git (for cloning the repository)

### Option 1: Local Installation

#### Step 1: Clone the Repository
```bash
git clone https://github.com/breakingcircuits1337/bcs-browser.git
cd bcs-browser
```

#### Step 2: Set Up Python Environment
We recommend using [uv](https://docs.astral.sh/uv/) for managing the Python environment.

Using uv (recommended):
```bash
uv venv --python 3.11
```

Activate the virtual environment:
- Windows (Command Prompt):
```cmd
.venv\Scripts\activate
```
- Windows (PowerShell):
```powershell
.\.venv\Scripts\Activate.ps1
```
- macOS/Linux:
```bash
source .venv/bin/activate
```

#### Step 3: Install Dependencies
Install Python packages:
```bash
uv pip install -r requirements.txt
```

Install Playwright:
```bash
playwright install
```

#### Step 4: Configure Environment
1. Create a copy of the example environment file:
- Windows (Command Prompt):
```bash
copy .env.example .env
```
- macOS/Linux/Windows (PowerShell):
```bash
cp .env.example .env
```
2. Open `.env` in your preferred text editor and add your API keys and other settings.

---

### Option 2: Docker Installation

#### Prerequisites
- Docker and Docker Compose installed

#### Installation Steps
1. Clone the repository:
```bash
git clone https://github.com/breakingcircuits1337/bcs-browser.git
cd bcs-browser
```

2. Create and configure environment file:
- Windows (Command Prompt):
```bash
copy .env.example .env
```
- macOS/Linux/Windows (PowerShell):
```bash
cp .env.example .env
```
Edit `.env` with your preferred text editor and add your API keys.

3. Run with Docker:
```bash
# Build and start the container with default settings
docker compose up --build
```
```bash
# Or run with persistent browser
CHROME_PERSISTENT_SESSION=true docker compose up --build
```

4. Access the Application:
- Web Interface: Open `http://localhost:7788` in your browser.
- VNC Viewer: Open `http://localhost:6080/vnc.html` to watch browser interactions.

---

## Usage

### Local Setup
1. **Run the WebUI**:
```bash
python webui.py --ip 127.0.0.1 --port 7788
```
2. **Access the WebUI**: Open `http://127.0.0.1:7788` in your browser.
3. **Configure Browser Settings**: Use the WebUI to set up your browser and LLM preferences.

### Docker Setup
1. **Environment Variables**: Configure settings in the `.env` file.
2. **Container Management**:
```bash
# Start with persistent browser
CHROME_PERSISTENT_SESSION=true docker compose up -d

# Stop the container
docker compose down
```

---

## Known Issues
- Some functions are still under development and may not work as expected.
- Browser persistence may occasionally fail on certain systems.

---

## Roadmap
- **Voice Control**: Adding voice-based interaction for hands-free operation.
- **Enhanced LLM Integration**: Expanding support for additional LLMs and improving existing integrations.
- **Improved Error Handling**: Making the system more robust and user-friendly.

---

## Contributing
We welcome contributions! Please open an issue or submit a pull request on [GitHub](https://github.com/breakingcircuits1337/bcs-browser). For detailed guidelines, check out our [Contributing Guide](#) (coming soon).

---

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments
- **[browser-use](https://github.com/browser-use/browser-use)**: For providing the foundational framework.
- **[WebUI](https://github.com/browser-use/web-ui)**: For the user-friendly interface.
- **[Breaking Circuits](https://breakingcircuits.com)**: For creating and maintaining this project.

---

## Support
For support, please open an issue on [GitHub](https://github.com/breakingcircuits1337/bcs-browser/issues) or visit **[Breaking Circuits](https://breakingcircuits.com)** for more information.

---

Let me know if you’d like further adjustments! 😊

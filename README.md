# Zashterm

<p align="center">
  <a href="https://github.com/leoberbert/zashterm/releases"><img src="https://img.shields.io/badge/Version-1.9.1-blue.svg" alt="Version"/></a>
  <a href="https://github.com/leoberbert/zashterm/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License"/></a>
</p>

**Zashterm** is a modern, intuitive, and innovative terminal built with GTK4 and Adwaita. While it offers advanced features appreciated by developers and system administrators, it also stands out for making the command-line environment more accessible, helping those who are just beginning to learn how to use the terminal. Its simplified session management, built-in file manager, automatic color highlighting for improved readability, and a variety of other features bring convenience to users of all skill levels on any Linux distribution.

## Screenshots

<img width="1457" height="699" alt="image" src="https://github.com/user-attachments/assets/080448b1-4fdd-44ba-8c70-6d70fb2651e5" />

<img width="1457" height="699" alt="image" src="https://github.com/user-attachments/assets/d79d710d-f60f-455e-a167-bb0527367264" />

<img width="1457" height="699" alt="image" src="https://github.com/user-attachments/assets/7c91e96b-114b-4da3-9c92-aae9f4a943fe" />

## Key Features

### 🤖 AI Assistant Integration
<img width="1457" height="699" alt="image" src="https://github.com/user-attachments/assets/ce5f1ebd-2527-4834-b5ca-cbf1c086efc6" />


Zashterm creates a bridge between your shell and Large Language Models (LLMs), offering an **optional** and fully **non-intrusive** AI experience. The assistant only processes the content that **you explicitly select and choose to send**, ensuring full control over your privacy.
* **Multi-Provider Support**: Native integration with **Groq**, **Google Gemini**, **OpenRouter**, and **Local LLMs** (Ollama/LM Studio).
* **Context Aware**: The AI understands your OS and distribution context to provide accurate and relevant commands.
* **Chat Panel**: A dedicated side panel for persistent conversations, command suggestions, and "Click-to-Run" code snippets.
* **Smart Suggestions**: Ask how to perform tasks and receive ready-to-execute commands directly in the UI.


### 🎨 Smart Context<img width="1386" height="944" alt="Zashterm colors1" src="https://github.com/user-attachments/assets/1674352a-b1ad-4668-b514-21c41306c58e" />
**Aware Highlighting**
<img width="1386" height="944" alt="Zashterm colors1" src="https://github.com/user-attachments/assets/ff8fb678-0aac-405a-a2c2-0835511a59db" />

Go beyond basic color schemes. Zashterm applies **dynamic, real-time highlighting** based on both the *content* and the *command being executed*—**without requiring any configuration in Bash or whatever shell you are using**. All color processing happens directly inside Zashterm’s interface, which is especially helpful when working on servers, containers, or restricted environments where you cannot modify files like `.bashrc` or `.zshrc`.

* **Command-Specific Rules**: Different highlighting rules are automatically applied when running tools such as `docker`, `ping`, `lspci`, `ip`, and more.
* **Live Input Highlighting**: Shell commands are colorized in real time as you type (powered by Pygments).
* **Output Colorization**: Automatically highlights IP addresses, UUIDs, URLs, error messages, JSON structures, and other patterns in logs.
* **File Viewer**: Enhances `cat` output with full syntax highlighting for code files.
<img width="1386" height="944" alt="Zashterm have color2" src="https://github.com/user-attachments/assets/10cc985e-a31f-4d45-bd64-57dfe68a91ef" />

In addition, Zashterm offers a **complete customization interface**, allowing you to adjust:
<img width="1386" height="944" alt="Zashterm have color3" src="https://github.com/user-attachments/assets/c42461ac-c8ae-41b7-883f-534ea9b333b8" />

* **Text and background colors**
* **Bold**, *italic*, ***underline***, ~~strikethrough~~
* **Blinking mode** for drawing attention to critical information
<img width="1386" height="944" alt="Zashterm have color4" src="https://github.com/user-attachments/assets/091e9c39-0958-49ca-8209-6c4c264a0c11" />

This gives you a clearer, more readable view of command output—especially in environments where traditional shell customization is not possible.


### 📂 Advanced File Manager & Remote Editing
<img width="823" height="1162" alt="image" src="https://github.com/user-attachments/assets/a112042a-ebca-41cd-a0bd-e4454a3eacf5" />
-   **Integrated Side Panel**: Browse local and remote file systems without leaving the terminal.
-   **Remote Editing**: Click to edit remote files (SSH/SFTP) in your favorite local editor. Zashterm watches the file and automatically uploads changes on save.
-   **Drag & Drop Transfer**: Upload files to remote servers simply by dragging them into the terminal window over (SFTP/Rsync)
-   **Transfer Manager**: Track uploads and downloads with a detailed progress manager and history.
<img width="1386" height="944" alt="image" src="https://github.com/user-attachments/assets/37d7e497-999d-4740-b9bb-cfec9cba17fc" />


### ⚡ Productivity Tools
<img width="458" height="422" alt="image" src="https://github.com/user-attachments/assets/eb16295b-00ea-4ab7-b6d4-a5fef3d40f6a" />
-   **Input Broadcasting**: Type commands in one terminal and execute them simultaneously across multiple selected tabs/panes.
-   **Quick Prompts**: One-click AI prompts for common tasks (e.g., "Explain this error", "Optimize this command").


### 🖥️ Core Terminal Functionality
-   **Session Management**: Save, organize (with folders), and launch Local, SSH, and SFTP sessions.
-   **Flexible Layouts**: Split panes horizontally and vertically; save and restore complex window layouts.
-   **Directory Tracking**: Updates tab titles automatically based on the current working directory (OSC7 support).
-   **Deep Customization**: Visual theme editor, font sizing, transparency (window and headerbar), and extensive keyboard shortcuts.


## Dependencies
To build and run Zashterm, you will need:

-   **Python 3.9+**
-   **GTK4** and **Adwaita 1.0+** (`libadwaita`)
-   **VTE for GTK4** (`vte4` >= 0.76 recommended)
-   **Python Libraries**:
    -   `PyGObject` (GTK bindings)
    -   `cryptography` (Secure password storage)
    -   `requests` (For AI API connectivity)
    -   `pygments` (For syntax highlighting)
    -   `psutil` (Optional, for advanced process tracking)
    -   `regex` (Optional, for high-performance highlighting patterns)

On an Arch/Manjaro-based system:
```bash
sudo pacman -S python python-gobject vte4 python-cryptography python-psutil python-requests python-pygments
````

## Installation

#### Prebuilt Packages (replace TAG/VERSION for the release you want)

Debian/Ubuntu (DEB):
```bash
TAG=v0.0.2
VERSION=0.0.2-1
cd /tmp
wget "https://github.com/leoberbert/zashterm/releases/download/${TAG}/zashterm_${VERSION}_amd64.deb"
sudo apt install "./zashterm_${VERSION}_amd64.deb"
```

Fedora/RHEL/openSUSE (RPM):
```bash
TAG=v0.0.2
VERSION=0.0.2-1
cd /tmp
wget "https://github.com/leoberbert/zashterm/releases/download/${TAG}/zashterm-${VERSION}.x86_64.rpm"
sudo dnf install "./zashterm-${VERSION}.x86_64.rpm"
```

Arch/Manjaro (PKG):
```bash
TAG=v0.0.2
VERSION=0.0.2-1-any
cd /tmp
wget "https://github.com/leoberbert/zashterm/releases/download/${TAG}/zashterm-${VERSION}.pkg.tar.zst"
sudo pacman -U "zashterm-${VERSION}.pkg.tar.zst"
```
## Usage

```bash
zashterm [options] [directory]
```

#### Arguments

| Option | Description |
|--------|-------------|
| `-w, --working-directory DIR` | Set initial working directory |
| `-e, -x, --execute COMMAND` | Execute command on startup (all remaining args are included) |
| `--close-after-execute` | Close the terminal tab after the command finishes |
| `--ssh [USER@]HOST` | Immediately connect to an SSH host |
| `--new-window` | Force opening a new window instead of a tab |

#### Examples

```bash
# Open terminal in a specific directory
zashterm ~/projects

# Execute a command
zashterm -e htop

# SSH connection
zashterm --ssh user@server.example.com

# Execute command and close after completion
zashterm --close-after-execute -e "ls -la"
```

## Configuration

Configuration files are stored in `~/.config/zashterm/`:

| File/Directory | Description |
|----------------|-------------|
| `settings.json` | General preferences, appearance, terminal behavior, shortcuts, and AI configuration |
| `sessions.json` | Saved SSH/SFTP connections and session folders |
| `session_state.json` | Window state and session restore data |
| `layouts/` | Saved window layouts (split panes configuration) |
| `logs/` | Application logs (when logging to file is enabled) |
| `backups/` | Manual encrypted backup archives |

**Note**: Syntax highlighting rules are bundled with the application in `data/highlights/` and include rules for 50+ commands (docker, git, systemctl, kubectl, and more).

## Contributing

Contributions are welcome\!

1.  Fork the repository.
2.  Create your feature branch (`git checkout -b feature/amazing-feature`).
3.  Commit your changes.
4.  Push to the branch.
5.  Open a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

  - Developers of **GNOME**, **GTK**, **VTE**, and **Pygments**.

<!-- end list -->

```

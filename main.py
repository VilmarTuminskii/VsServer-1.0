import paramiko, customtkinter as ctk, json, os, hashlib, re, threading, logging, time
from tkinter import messagebox, ttk, filedialog
from datetime import datetime
from cryptography.fernet import Fernet
from dataclasses import dataclass
from typing import Optional, List
import uuid

# Constants
CONFIG_FILE, LOG_FILE = "config.json", "logs_servidores.log"
DEFAULT_SENHA, ADMIN_CREDENTIALS = "asd@123", {"admin": hashlib.sha256("admin123".encode()).hexdigest()}
ENCRYPTION_KEY_FILE = "encryption_key.key"
COLORS = {"primary": "#3B82F6", "secondary": "#1E40AF", "background": "#1A1A1A", "card": "#2C2C2C",
          "text": "#E5E5E5", "success": "#22C55E", "error": "#EF4444", "border": "#3F3F3F"}
FONTS = {"title": ("Inter", 22, "bold"), "subtitle": ("Inter", 15, "bold"), "label": ("Inter", 13), "button": ("Inter", 13, "bold")}
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

@dataclass
class ServerConnection:
    id: str
    name: str
    ip: str
    username: str
    password: Optional[str] = None
    save_password: bool = False

class UserManagerApp:
    def __init__(self):
        self.app = ctk.CTk()
        self.app.title("VsServer")
        self.app.geometry("1200x720")
        self.app.minsize(1000, 600)
        ctk.set_appearance_mode("dark")
        self.logged_in, self.is_processing = False, False
        self.encryption_key = self._load_key()
        self.connections, self.current_connection = [], None
        self.config = self._load_config()
        self.resize_timeout, self.last_window_size = None, (1200, 720)
        self.menu_buttons = []
        self.app.bind("<Configure>", self._debounce_resize)
        self.setup_ui()

    def _load_key(self) -> bytes:
        if os.path.exists(ENCRYPTION_KEY_FILE):
            with open(ENCRYPTION_KEY_FILE, "rb") as f: return f.read()
        key = Fernet.generate_key()
        with open(ENCRYPTION_KEY_FILE, "wb") as f: f.write(key)
        return key

    def _encrypt(self, password: str) -> Optional[str]:
        try: return Fernet(self.encryption_key).encrypt(password.encode()).decode()
        except Exception as e: logging.error(f"Erro ao criptografar: {e}"); return None

    def _decrypt(self, encrypted: str) -> Optional[str]:
        try: return Fernet(self.encryption_key).decrypt(encrypted.encode()).decode()
        except Exception as e: logging.error(f"Erro ao descriptografar: {e}"); return None

    def _save_config(self):
        config = {
            "connections": [{"id": c.id, "name": c.name, "ip": c.ip, "username": c.username,
                             "save_password": c.save_password, "password": self._encrypt(self.entry_senha_ssh.get().strip())
                             if c.save_password else None} for c in self.connections],
            "last_connection_id": self.current_connection.id if self.current_connection else None
        }
        if os.path.exists(CONFIG_FILE):
            os.rename(CONFIG_FILE, f"{CONFIG_FILE}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        with open(CONFIG_FILE, "w") as f: json.dump(config, f, indent=4)
        self.config = config

    def _load_config(self) -> dict:
        if not os.path.exists(CONFIG_FILE): return {}
        with open(CONFIG_FILE, "r") as f: config = json.load(f)
        self.connections = [ServerConnection(id=c.get("id", str(uuid.uuid4())), name=c.get("name", f"Servidor {i+1}"),
                                            ip=c.get("ip", ""), username=c.get("username", ""),
                                            save_password=c.get("save_password", False), password=c.get("password"))
                            for i, c in enumerate(config.get("connections", []))]
        self.current_connection = next((c for c in self.connections if c.id == config.get("last_connection_id")), None)
        return config

    def _debounce_resize(self, event):
        if self.resize_timeout: self.app.after_cancel(self.resize_timeout)
        self.resize_timeout = self.app.after(200, self._update_sizes)

    def _update_sizes(self):
        if not hasattr(self, 'sidebar') or not self.sidebar or not self.sidebar.winfo_exists(): return
        w, h = self.app.winfo_width(), self.app.winfo_height()
        if abs(w - self.last_window_size[0]) < 5 and abs(h - self.last_window_size[1]) < 5: return
        self.last_window_size = (w, h)
        sidebar_w, font_size = max(250, min(int(w * 0.22), 300)), 13 if h < 700 else 14
        entry_w, content_w, content_h = max(300, int(w * 0.35)), max(450, int(w * 0.7)), max(350, int(h * 0.65))
        self.sidebar.configure(width=sidebar_w)
        for e in [self.entry_ip, self.entry_usuario_ssh, self.entry_senha_ssh, self.combo_connections]:
            if e.winfo_exists(): e.configure(width=sidebar_w - 40, font=("Inter", font_size))
        for w in self.content_frame.winfo_children():
            if isinstance(w, ctk.CTkFrame) and w.winfo_exists():
                for c in w.winfo_children():
                    if isinstance(c, (ctk.CTkEntry, ctk.CTkComboBox)) and c.winfo_exists():
                        c.configure(width=entry_w, font=("Inter", font_size))
                    elif isinstance(c, ctk.CTkTextbox) and c.winfo_exists():
                        c.configure(width=content_w, height=content_h, font=("Inter", font_size))
                    elif isinstance(c, ttk.Treeview) and c.winfo_exists():
                        c.configure(height=int(content_h / 25))

    def _show_message(self, title: str, message: str, type_: str = "error"):
        self.app.after(0, lambda: getattr(messagebox, f"show{type_}")(title, message))

    def _create_entry(self, parent, label, placeholder, show="", attr=None):
        ctk.CTkLabel(parent, text=label, font=FONTS["label"], text_color=COLORS["text"]).pack(anchor="w", pady=(8, 2), padx=10)
        entry = ctk.CTkEntry(parent, font=FONTS["label"], corner_radius=6, placeholder_text=placeholder, show=show, border_color=COLORS["border"])
        entry.pack(fill="x", pady=4, padx=10)
        if attr: setattr(self, attr, entry)
        return entry

    def _create_button(self, parent, text, cmd, fg_color, hover_color, side=None, fill="x", expand=True, padx=8):
        btn = ctk.CTkButton(parent, text=text, command=cmd, font=FONTS["button"], fg_color=fg_color, hover_color=hover_color, corner_radius=6, height=36)
        btn.pack(side=side, fill=fill, expand=expand, padx=padx, pady=8)
        return btn

    def _create_card(self, parent, title):
        card = ctk.CTkFrame(parent, fg_color=COLORS["card"], corner_radius=12, border_color=COLORS["border"], border_width=1)
        card.pack(fill="both", expand=True, padx=15, pady=15)
        ctk.CTkLabel(card, text=title, font=FONTS["title"], text_color=COLORS["text"]).pack(anchor="w", pady=(15, 8), padx=15)
        return card

    def _show_login(self):
        self._clear_window()
        frame = ctk.CTkFrame(self.app, fg_color="transparent")
        frame.place(relx=0.5, rely=0.5, anchor="center")
        card = ctk.CTkFrame(frame, fg_color=COLORS["card"], corner_radius=15, border_width=1, border_color=COLORS["border"])
        card.pack(pady=40, padx=80)
        ctk.CTkLabel(card, text="VsServer", font=FONTS["title"], text_color=COLORS["text"]).pack(pady=(20, 28))
        ctk.CTkLabel(card, text="Gerenciador de Servidores", font=FONTS["subtitle"], text_color=COLORS["text"]).pack(pady=(0, 20))
        input_frame = ctk.CTkFrame(card, fg_color="transparent")
        input_frame.pack(padx=30, pady=8, fill="x")
        self.entry_admin_user = self._create_entry(input_frame, "Usuário", "Digite o usuário", attr="entry_admin_user")
        self.entry_admin_pass = self._create_entry(input_frame, "Senha", "Digite a senha", show="*", attr="entry_admin_pass")
        self._create_button(card, "Entrar", self._verify_login, COLORS["primary"], COLORS["secondary"], padx=30)
        self.entry_admin_pass.bind("<Return>", lambda _: self._verify_login())

    def _verify_login(self):
        username, password = self.entry_admin_user.get().strip(), hashlib.sha256(self.entry_admin_pass.get().strip().encode()).hexdigest()
        if username in ADMIN_CREDENTIALS and ADMIN_CREDENTIALS[username] == password:
            self.logged_in = True
            logging.info(f"Login: {username}")
            self._show_main()
        else:
            logging.warning(f"Falha no login: {username}")
            self._show_message("Erro", "Credenciais inválidas!")
            self.entry_admin_pass.configure(border_color=COLORS["error"])

    def _show_main(self):
        self._clear_window()
        top_bar = ctk.CTkFrame(self.app, height=50, fg_color=COLORS["primary"], corner_radius=0)
        top_bar.pack(side="top", fill="x")
        ctk.CTkLabel(top_bar, text="VsServer - Gerenciador de Servidores", font=FONTS["title"], text_color=COLORS["text"]).pack(pady=10, padx=15, anchor="w")
        self.main_container = ctk.CTkFrame(self.app, fg_color=COLORS["background"])
        self.main_container.pack(fill="both", expand=True)
        self.main_container.grid_rowconfigure(0, weight=1)
        self.main_container.grid_columnconfigure(1, weight=1)
        self.sidebar = ctk.CTkFrame(self.main_container, fg_color=COLORS["card"], corner_radius=0, width=250)
        self.sidebar.grid(row=0, column=0, sticky="nsw", pady=0, padx=0)
        conn_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        conn_frame.pack(fill="x", padx=15, pady=(15, 8))
        ctk.CTkLabel(conn_frame, text="Conexões", font=FONTS["subtitle"], text_color=COLORS["text"]).pack(anchor="w", pady=(0, 8))
        self.combo_connections = ctk.CTkComboBox(conn_frame, font=FONTS["label"], corner_radius=6, values=[c.name for c in self.connections], command=self._select_connection, border_color=COLORS["border"])
        self.combo_connections.pack(fill="x", pady=4)
        self.entry_ip = self._create_entry(conn_frame, "IP", "Ex: 192.168.1.1", attr="entry_ip")
        self.entry_usuario_ssh = self._create_entry(conn_frame, "Usuário SSH", "Digite o usuário SSH", attr="entry_usuario_ssh")
        self.entry_senha_ssh = self._create_entry(conn_frame, "Senha SSH", "Digite a senha SSH", show="*", attr="entry_senha_ssh")
        self.var_save_password = ctk.BooleanVar(value=self.current_connection.save_password if self.current_connection else False)
        ctk.CTkCheckBox(conn_frame, text="Salvar Senha", font=FONTS["label"], variable=self.var_save_password, command=self._warn_password, text_color=COLORS["text"]).pack(anchor="w", pady=8, padx=10)
        btn_frame = ctk.CTkFrame(conn_frame, fg_color="transparent")
        btn_frame.pack(fill="x", pady=8)
        for text, cmd, color, hover in [("Nova", self._add_connection, COLORS["primary"], COLORS["secondary"]),
                                        ("Editar", self._edit_connection, COLORS["primary"], COLORS["secondary"]),
                                        ("Remover", self._remove_connection, COLORS["error"], "#9A1C1C")]:
            self._create_button(btn_frame, text, cmd, color, hover, side="left", fill=None, expand=False, padx=4)
        menu_frame = ctk.CTkScrollableFrame(self.sidebar, fg_color="transparent", corner_radius=0, scrollbar_button_color=COLORS["primary"])
        menu_frame.pack(fill="both", expand=True, padx=15, pady=15)
        ctk.CTkLabel(menu_frame, text="Ferramentas", font=FONTS["subtitle"], text_color=COLORS["text"]).pack(anchor="w", pady=(0, 8))
        for text, cmd in [("Gerenciar Usuários", self._show_user_management), ("Listar Usuários", self._list_users),
                          ("Espaço em Disco", self._check_disk), ("Resetar Senha", self._reset_password),
                          ("Gerenciar Grupos", self._show_group_management), ("Bloquear/Desbloquear", self._show_lock_unlock),
                          ("Monitorar Atividade", self._monitor_activity), ("Backup Config", self._show_backup),
                          ("Comandos Personalizados", self._show_custom_cmd), ("Histórico", self._show_history),
                          ("Testar Conexão", self._test_connection)]:
            btn = ctk.CTkButton(menu_frame, text=text, command=lambda c=cmd: self._run_thread(c), font=FONTS["label"], fg_color="transparent", hover_color=COLORS["secondary"], corner_radius=6, anchor="w", text_color=COLORS["text"], height=34)
            btn.pack(fill="x", pady=2)
            self.menu_buttons.append(btn)
        self.content_frame = ctk.CTkFrame(self.main_container, fg_color=COLORS["background"], corner_radius=0)
        self.content_frame.grid(row=0, column=1, sticky="nsew", padx=15, pady=15)
        if self.current_connection:
            self.entry_ip.insert(0, self.current_connection.ip)
            self.entry_usuario_ssh.insert(0, self.current_connection.username)
            if self.current_connection.save_password and self.current_connection.password:
                if decrypted := self._decrypt(self.current_connection.password): self.entry_senha_ssh.insert(0, decrypted)
        self._show_user_management()
        self._update_sizes()

    def _select_connection(self, choice: str):
        self.current_connection = next((c for c in self.connections if c.name == choice), None)
        if self.current_connection:
            for e in [self.entry_ip, self.entry_usuario_ssh, self.entry_senha_ssh]: e.delete(0, ctk.END)
            self.entry_ip.insert(0, self.current_connection.ip)
            self.entry_usuario_ssh.insert(0, self.current_connection.username)
            if self.current_connection.save_password and self.current_connection.password:
                if decrypted := self._decrypt(self.current_connection.password): self.entry_senha_ssh.insert(0, decrypted)
            self.var_save_password.set(self.current_connection.save_password)
            self._save_config()
            self.combo_connections.configure(state="normal")

    def _add_edit_connection(self, edit=False):
        if edit and not self.current_connection: 
            self._show_message("Erro", "Nenhuma conexão selecionada.")
            return
        dialog = ctk.CTkToplevel(self.app)
        dialog.title("Editar Conexão" if edit else "Nova Conexão")
        dialog.geometry("400x550")
        dialog.resizable(False, False)
        frame = ctk.CTkFrame(dialog, fg_color=COLORS["card"], corner_radius=12, border_width=1, border_color=COLORS["border"])
        frame.pack(pady=10, padx=10, fill="both", expand=True)
        ctk.CTkLabel(frame, text="Editar Conexão" if edit else "Nova Conexão", font=FONTS["subtitle"], text_color=COLORS["text"]).pack(pady=(15, 8))
        entries = {}
        values = [self.current_connection.name, self.current_connection.ip, self.current_connection.username,
                  self._decrypt(self.current_connection.password) if self.current_connection.password else ""] if edit else ["", "", "", ""]
        for label, placeholder, value, show in [("Nome da Conexão", "Nome da conexão", values[0], ""),
                                               ("IP", "Ex: 192.168.1.1", values[1], ""),
                                               ("Usuário SSH", "Digite o usuário SSH", values[2], ""),
                                               ("Senha SSH", "Digite a senha SSH", values[3], "*")]:
            entries[label] = self._create_entry(frame, label, placeholder, show)
            entries[label].insert(0, value)
        var_save_password = ctk.BooleanVar(value=self.current_connection.save_password if edit else False)
        ctk.CTkCheckBox(frame, text="Salvar Senha", font=FONTS["label"], variable=var_save_password, text_color=COLORS["text"]).pack(anchor="w", padx=10, pady=8)
        def save():
            name, ip, username, password = [entries[l].get().strip() for l in ["Nome da Conexão", "IP", "Usuário SSH", "Senha SSH"]]
            if not all([name, ip, username, password]): 
                self._show_message("Erro", "Preencha todos os campos.")
                return
            if not re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ip):
                self._show_message("Erro", "IP inválido.")
                return
            if edit:
                self.current_connection.name, self.current_connection.ip, self.current_connection.username = name, ip, username
                self.current_connection.password = self._encrypt(password) if var_save_password.get() else None
                self.current_connection.save_password = var_save_password.get()
            else:
                self.connections.append(ServerConnection(str(uuid.uuid4()), name, ip, username, self._encrypt(password) if var_save_password.get() else None, var_save_password.get()))
                self.current_connection = self.connections[-1]
            self._update_connections()
            self._save_config()
            dialog.destroy()
            self._select_connection(name)
            self._show_message("Sucesso", f"Conexão {'atualizada' if edit else 'adicionada'}.", "info")
        self._create_button(frame, "Salvar", save, COLORS["primary"], COLORS["secondary"], padx=10)
        dialog.transient(self.app)
        dialog.grab_set()

    def _add_connection(self): self._add_edit_connection()
    def _edit_connection(self): self._add_edit_connection(edit=True)

    def _remove_connection(self):
        if not self.current_connection: 
            self._show_message("Erro", "Nenhuma conexão selecionada.")
            return
        if not messagebox.askyesno("Confirmação", f"Remover '{self.current_connection.name}'?"): return
        self.connections.remove(self.current_connection)
        self.current_connection = None
        self._update_connections()
        self._save_config()
        for e in [self.entry_ip, self.entry_usuario_ssh, self.entry_senha_ssh]: e.delete(0, ctk.END)
        self._show_message("Sucesso", "Conexão removida.", "info")

    def _update_connections(self):
        self.combo_connections.configure(values=[c.name for c in self.connections], state="normal")
        if self.current_connection:
            self.combo_connections.set(self.current_connection.name)
        elif self.connections:
            self.combo_connections.set(self.connections[0].name)
            self._select_connection(self.connections[0].name)
        else:
            self.combo_connections.set("")

    def _warn_password(self):
        if self.var_save_password.get() and not messagebox.askyesno("Aviso", "Salvar a senha pode ser um risco de segurança.\nDeseja continuar?", icon="warning"):
            self.var_save_password.set(False)
        if self.current_connection:
            self.current_connection.save_password = self.var_save_password.get()
            if not self.var_save_password.get(): self.current_connection.password = None
            self._save_config()

    def _show_user_management(self):
        self._clear_content()
        card = self._create_card(self.content_frame, "Gerenciar Usuários")
        form_frame = ctk.CTkFrame(card, fg_color="transparent")
        form_frame.pack(fill="x", padx=15, pady=8)
        self.entry_nome = self._create_entry(form_frame, "Nome do Usuário", "Digite o nome do usuário", attr="entry_nome")
        self.entry_senha_usuario = self._create_entry(form_frame, "Senha (Opcional)", f"Deixe em branco para padrão: {DEFAULT_SENHA}", show="*", attr="entry_senha_usuario")
        ctk.CTkLabel(form_frame, text="Grupo", font=FONTS["label"], text_color=COLORS["text"]).pack(anchor="w", pady=(8, 2), padx=10)
        self.combo_grupo = ctk.CTkComboBox(form_frame, font=FONTS["label"], corner_radius=6, values=["", "sambagrupo", "developers", "ti", "financeiro"], dropdown_fg_color=COLORS["card"], button_color=COLORS["primary"], border_color=COLORS["border"])
        self.combo_grupo.pack(fill="x", pady=4, padx=10)
        self.var_samba = ctk.BooleanVar()
        ctk.CTkCheckBox(form_frame, text="Adicionar ao Samba", font=FONTS["label"], variable=self.var_samba, text_color=COLORS["text"]).pack(anchor="w", pady=8, padx=10)
        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(fill="x", pady=15, padx=15)
        for text, cmd, color, hover in [("Criar Usuário", self._create_user, COLORS["primary"], COLORS["secondary"]),
                                        ("Deletar Usuário", self._delete_user, COLORS["error"], "#9A1C1C")]:
            self._create_button(btn_frame, text, lambda c=cmd: self._run_thread(c), color, hover, side="left", fill="x", expand=True, padx=8)

    def _show_group_management(self):
        self._clear_content()
        card = self._create_card(self.content_frame, "Gerenciar Grupos")
        form_frame = ctk.CTkFrame(card, fg_color="transparent")
        form_frame.pack(fill="x", padx=15, pady=8)
        self.entry_group = self._create_entry(form_frame, "Nome do Grupo", "Digite o nome do grupo", attr="entry_group")
        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(fill="x", pady=15, padx=15)
        for text, cmd, color, hover in [("Criar Grupo", self._create_group, COLORS["primary"], COLORS["secondary"]),
                                        ("Deletar Grupo", self._delete_group, COLORS["error"], "#9A1C1C"),
                                        ("Listar Grupos", self._list_groups, COLORS["primary"], COLORS["secondary"])]:
            self._create_button(btn_frame, text, lambda c=cmd: self._run_thread(c), color, hover, side="left", fill="x", expand=True, padx=8)

    def _show_lock_unlock(self):
        self._clear_content()
        card = self._create_card(self.content_frame, "Bloquear/Desbloquear Usuário")
        form_frame = ctk.CTkFrame(card, fg_color="transparent")
        form_frame.pack(fill="x", padx=15, pady=8)
        self.entry_lock_user = self._create_entry(form_frame, "Nome do Usuário", "Digite o nome do usuário", attr="entry_lock_user")
        self.var_lock_action = ctk.StringVar(value="Bloquear")
        action_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        action_frame.pack(fill="x", pady=8)
        for text, value in [("Bloquear", "Bloquear"), ("Desbloquear", "Desbloquear")]:
            ctk.CTkRadioButton(action_frame, text=text, font=FONTS["label"], variable=self.var_lock_action, value=value, text_color=COLORS["text"]).pack(side="left", padx=15)
        self._create_button(form_frame, "Executar", lambda: self._run_thread(self._lock_unlock_user), COLORS["primary"], COLORS["secondary"], padx=10)

    def _show_backup(self):
        self._clear_content()
        card = self._create_card(self.content_frame, "Backup de Configurações")
        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(fill="x", pady=15, padx=15)
        for text, cmd in [("Exportar Configuração", self._export_config), ("Importar Configuração", self._import_config)]:
            self._create_button(btn_frame, text, lambda c=cmd: self._run_thread(c), COLORS["primary"], COLORS["secondary"], side="left", fill="x", expand=True, padx=8)

    def _show_custom_cmd(self):
        self._clear_content()
        card = self._create_card(self.content_frame, "Comandos Personalizados")
        self.entry_custom_cmd = self._create_entry(card, "Comando", "Digite o comando SSH", attr="entry_custom_cmd")
        self._create_button(card, "Executar", lambda: self._run_thread(self._execute_custom), COLORS["primary"], COLORS["secondary"], padx=10)
        output_frame = ctk.CTkFrame(card, fg_color="transparent")
        output_frame.pack(fill="both", expand=True, padx=15, pady=8)
        self.custom_output = ctk.CTkTextbox(output_frame, font=FONTS["label"], state="disabled", wrap="none", fg_color=COLORS["background"])
        self.custom_output.pack(side="left", fill="both", expand=True)
        scrollbar = ctk.CTkScrollbar(output_frame, command=self.custom_output.yview, fg_color=COLORS["card"], button_color=COLORS["primary"])
        scrollbar.pack(side="right", fill="y")
        self.custom_output.configure(yscrollcommand=scrollbar.set)

    def _clear_window(self):
        for w in self.app.winfo_children(): w.destroy()
        self.loading_frame = self.progress = self.status_label = None

    def _clear_content(self):
        for w in self.content_frame.winfo_children(): w.destroy()
        self.progress = self.status_label = None

    def _show_loading(self, message="Processando"):
        if not hasattr(self, 'loading_frame') or not self.loading_frame or not self.loading_frame.winfo_exists():
            self.loading_frame = ctk.CTkToplevel(self.app, fg_color=COLORS["card"])
            self.loading_frame.geometry("300x150")
            self.loading_frame.resizable(False, False)
            self.loading_frame.transient(self.app)
            screen_width = self.app.winfo_screenwidth()
            screen_height = self.app.winfo_screenheight()
            x = (screen_width - 300) // 2
            y = (screen_height - 150) // 2
            self.loading_frame.geometry(f"300x150+{x}+{y}")
            ctk.CTkLabel(self.loading_frame, text="Aguarde...", font=FONTS["subtitle"], text_color=COLORS["text"]).pack(pady=10)
            self.progress = ctk.CTkProgressBar(self.loading_frame, mode="indeterminate", width=200, progress_color=COLORS["primary"])
            self.progress.pack(pady=10)
            self.status_label = ctk.CTkLabel(self.loading_frame, text=f"{message}...", font=FONTS["label"], text_color=COLORS["text"])
            self.status_label.pack(pady=10)
            self.progress.start()
            self.app.after(200, self._update_status)

    def _update_status(self):
        if self.status_label and self.status_label.winfo_exists():
            dots = self.status_label.cget("text").count(".") % 3 + 1
            self.status_label.configure(text=f"Processando{'.' * dots}")
            self.app.after(200, self._update_status)

    def _hide_loading(self):
        if hasattr(self, 'progress') and self.progress and self.progress.winfo_exists(): self.progress.stop()
        if hasattr(self, 'loading_frame') and self.loading_frame and self.loading_frame.winfo_exists(): self.loading_frame.destroy()
        self.loading_frame = self.progress = self.status_label = None

    def _set_buttons(self, state="normal"):
        for btn in self.menu_buttons: 
            if btn.winfo_exists(): btn.configure(state=state)
        for w in self.content_frame.winfo_children():
            if isinstance(w, ctk.CTkFrame) and w.winfo_exists():
                for c in w.winfo_children():
                    if isinstance(c, ctk.CTkButton) and c.winfo_exists(): c.configure(state=state)

    def _run_thread(self, func):
        if self.is_processing: 
            self._show_message("Aviso", "Aguarde a operação atual.", "warning")
            return
        self.is_processing = True
        self._set_buttons("disabled")
        self._show_loading(func.__name__.replace('_', ' ').title())
        threading.Thread(target=lambda: (func(), self.app.after(0, lambda: (self._set_buttons("normal"), self._hide_loading(), setattr(self, 'is_processing', False)))), daemon=True).start()

    def _validate_connection(self) -> bool:
        ip, user, pwd = [getattr(self, f"entry_{x}").get().strip() for x in ["ip", "usuario_ssh", "senha_ssh"]]
        if not all([ip, user, pwd]):
            self._show_message("Erro", "Preencha todos os campos de conexão.")
            for e, v in [(self.entry_ip, ip), (self.entry_usuario_ssh, user), (self.entry_senha_ssh, pwd)]: e.configure(border_color=COLORS["error"] if not v else COLORS["border"])
            return False
        if not re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ip):
            self._show_message("Erro", "IP inválido.")
            self.entry_ip.configure(border_color=COLORS["error"])
            return False
        return True

    def _connect_ssh(self) -> Optional[paramiko.SSHClient]:
        if not self._validate_connection(): return None
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=self.entry_ip.get().strip(), username=self.entry_usuario_ssh.get().strip(), password=self.entry_senha_ssh.get().strip(), timeout=10)
            logging.info(f"Conexão SSH: {self.entry_ip.get()}")
            return client
        except Exception as e:
            logging.error(f"Falha na conexão SSH: {e}")
            self._show_message("Erro", f"Falha na conexão SSH: {e}")
            return None

    def _execute_sudo(self, channel, cmd: str, pwd: str, extra_input: Optional[str] = None) -> str:
        channel.send(f"{cmd}\n")
        time.sleep(0.2)
        output = ""
        while channel.recv_ready(): output += channel.recv(65535).decode()
        if "[sudo] password" in output:
            channel.send(f"{pwd}\n")
            time.sleep(0.2)
        if extra_input:
            channel.send(extra_input)
            time.sleep(0.2)
        output, error = "", ""
        while channel.recv_ready(): output += channel.recv(65535).decode()
        while channel.recv_stderr_ready(): error += channel.recv_stderr(65535).decode()
        if error and "already exists" not in error and "does not exist" not in error: raise Exception(error)
        return output

    def _create_user(self):
        if not self._validate_connection(): return
        nome, senha, grupo, samba, pwd_ssh = self.entry_nome.get().strip(), self.entry_senha_usuario.get().strip() or DEFAULT_SENHA, self.combo_grupo.get().strip(), self.var_samba.get(), self.entry_senha_ssh.get().strip()
        if not nome or not re.match(r"^[a-z][a-z0-9_-]{2,15}$", nome):
            self._show_message("Erro", "Nome inválido (3-16 caracteres alfanuméricos).")
            self.entry_nome.configure(border_color=COLORS["error"])
            return
        client = self._connect_ssh()
        if not client: return
        try:
            channel = client.invoke_shell()
            commands = [(f"sudo -S useradd -m -s /bin/bash {nome}", None, "Erro ao criar usuário"),
                        (f"sudo -S chpasswd", f"{nome}:{senha}\n", "Erro ao definir senha")]
            if grupo: commands.append((f"sudo -S usermod -aG {grupo} {nome}", None, f"Erro ao adicionar ao grupo {grupo}"))
            if samba: commands.append((f"sudo -S smbpasswd -a {nome}", f"{senha}\n{senha}\n", "Erro ao configurar Samba"))
            for cmd, input_, _ in commands: self._execute_sudo(channel, cmd, pwd_ssh, input_)
            channel.close()
            logging.info(f"Usuário '{nome}' criado | Grupo: {grupo} | Samba: {samba}")
            self._save_config()
            self._show_message("Sucesso", f"Usuário '{nome}' criado.", "info")
            for e in [self.entry_nome, self.entry_senha_usuario]: e.delete(0, ctk.END); e.configure(border_color=COLORS["success"])
        except Exception as e:
            logging.error(f"Falha na criação do usuário '{nome}': {e}")
            self._show_message("Erro", f"Falha na criação: {e}")
            for e in [self.entry_nome, self.entry_senha_usuario]: e.configure(border_color=COLORS["error"])
        finally:
            client.close()

    def _delete_user(self):
        if not self._validate_connection(): return
        nome, pwd_ssh = self.entry_nome.get().strip(), self.entry_senha_ssh.get().strip()
        if not nome or not re.match(r"^[a-z][a-z0-9_-]{2,15}$", nome):
            self._show_message("Erro", "Nome inválido (3-16 caracteres alfanuméricos).")
            self.entry_nome.configure(border_color=COLORS["error"])
            return
        if not messagebox.askyesno("Confirmação", f"Deletar usuário '{nome}'?"): return
        client = self._connect_ssh()
        if not client: return
        try:
            channel = client.invoke_shell()
            for cmd, input_ in [(f"sudo -S userdel -r {nome}", None), (f"sudo -S smbpasswd -x {nome}", None)]:
                try: self._execute_sudo(channel, cmd, pwd_ssh, input_)
                except Exception as e: 
                    if "does not exist" not in str(e): raise
            channel.close()
            logging.info(f"Usuário '{nome}' deletado")
            self._save_config()
            self._show_message("Sucesso", f"Usuário '{nome}' deletado.", "info")
            self.entry_nome.delete(0, ctk.END)
            self.entry_nome.configure(border_color=COLORS["success"])
        except Exception as e:
            logging.error(f"Falha na deleção do usuário '{nome}': {e}")
            self._show_message("Erro", f"Falha na deleção: {e}")
            self.entry_nome.configure(border_color=COLORS["error"])
        finally:
            client.close()

    def _create_group(self):
        if not self._validate_connection(): return
        group, pwd_ssh = self.entry_group.get().strip(), self.entry_senha_ssh.get().strip()
        if not group or not re.match(r"^[a-z][a-z0-9_-]{2,15}$", group):
            self._show_message("Erro", "Nome de grupo inválido (3-16 caracteres alfanuméricos).")
            self.entry_group.configure(border_color=COLORS["error"])
            return
        client = self._connect_ssh()
        if not client: return
        try:
            channel = client.invoke_shell()
            self._execute_sudo(channel, f"sudo -S groupadd {group}", pwd_ssh)
            channel.close()
            logging.info(f"Grupo '{group}' criado")
            self._show_message("Sucesso", f"Grupo '{group}' criado.", "info")
            self.entry_group.delete(0, ctk.END)
            self.entry_group.configure(border_color=COLORS["success"])
        except Exception as e:
            logging.error(f"Falha na criação do grupo '{group}': {e}")
            self._show_message("Erro", f"Falha na criação: {e}")
            self.entry_group.configure(border_color=COLORS["error"])
        finally:
            client.close()

    def _delete_group(self):
        if not self._validate_connection(): return
        group, pwd_ssh = self.entry_group.get().strip(), self.entry_senha_ssh.get().strip()
        if not group or not re.match(r"^[a-z][a-z0-9_-]{2,15}$", group):
            self._show_message("Erro", "Nome de grupo inválido (3-16 caracteres alfanuméricos).")
            self.entry_group.configure(border_color=COLORS["error"])
            return
        if not messagebox.askyesno("Confirmação", f"Deletar grupo '{group}'?"): return
        client = self._connect_ssh()
        if not client: return
        try:
            channel = client.invoke_shell()
            self._execute_sudo(channel, f"sudo -S groupdel {group}", pwd_ssh)
            channel.close()
            logging.info(f"Grupo '{group}' deletado")
            self._show_message("Sucesso", f"Grupo '{group}' deletado.", "info")
            self.entry_group.delete(0, ctk.END)
            self.entry_group.configure(border_color=COLORS["success"])
        except Exception as e:
            logging.error(f"Falha na deleção do grupo '{group}': {e}")
            self._show_message("Erro", f"Falha na deleção: {e}")
            self.entry_group.configure(border_color=COLORS["error"])
        finally:
            client.close()

    def _list_groups(self):
        self._clear_content()
        client = self._connect_ssh()
        if not client: return
        card = self._create_card(self.content_frame, "Grupos do Sistema")
        tree_frame = ctk.CTkFrame(card, fg_color="transparent")
        tree_frame.pack(fill="both", expand=True, padx=15, pady=8)
        tree = ttk.Treeview(tree_frame, columns=("Grupo",), show="headings", style="Custom.Treeview")
        tree.heading("Grupo", text="Grupo")
        tree.pack(side="left", fill="both", expand=True)
        scrollbar = ctk.CTkScrollbar(tree_frame, command=tree.yview, fg_color=COLORS["card"], button_color=COLORS["primary"])
        scrollbar.pack(side="right", fill="y")
        tree.configure(yscrollcommand=scrollbar.set)
        style = ttk.Style()
        style.configure("Custom.Treeview", font=FONTS["label"], rowheight=25, background=COLORS["card"], foreground=COLORS["text"], fieldbackground=COLORS["card"])
        style.configure("Custom.Treeview.Heading", font=FONTS["subtitle"], background=COLORS["border"])
        try:
            _, stdout, _ = client.exec_command("getent group | cut -d: -f1")
            for group in stdout.read().decode().splitlines(): tree.insert("", "end", values=(group,))
            logging.info("Grupos listados")
        except Exception as e:
            logging.error(f"Falha ao listar grupos: {e}")
            self._show_message("Erro", f"Falha ao listar: {e}")
        finally:
            client.close()
        self._update_sizes()

    def _lock_unlock_user(self):
        if not self._validate_connection(): return
        username, action, pwd_ssh = self.entry_lock_user.get().strip(), self.var_lock_action.get(), self.entry_senha_ssh.get().strip()
        if not username or not re.match(r"^[a-z][a-z0-9_-]{2,15}$", username):
            self._show_message("Erro", "Nome inválido (3-16 caracteres alfanuméricos).")
            self.entry_lock_user.configure(border_color=COLORS["error"])
            return
        client = self._connect_ssh()
        if not client: return
        try:
            channel = client.invoke_shell()
            self._execute_sudo(channel, f"sudo -S usermod -{'L' if action == 'Bloquear' else 'U'} {username}", pwd_ssh)
            channel.close()
            logging.info(f"Usuário '{username}' {'bloqueado' if action == 'Bloquear' else 'desbloqueado'}")
            self._show_message("Sucesso", f"Usuário '{username}' {'bloqueado' if action == 'Bloquear' else 'desbloqueado'}.", "info")
            self.entry_lock_user.delete(0, ctk.END)
            self.entry_lock_user.configure(border_color=COLORS["success"])
        except Exception as e:
            logging.error(f"Falha ao {'bloquear' if action == 'Bloquear' else 'desbloquear'} usuário '{username}': {e}")
            self._show_message("Erro", f"Falha ao {'bloquear' if action == 'Bloquear' else 'desbloquear'}: {e}")
            self.entry_lock_user.configure(border_color=COLORS["error"])
        finally:
            client.close()

    def _monitor_activity(self):
        self._clear_content()
        client = self._connect_ssh()
        if not client: return
        card = self._create_card(self.content_frame, "Atividade de Usuários")
        tree_frame = ctk.CTkFrame(card, fg_color="transparent")
        tree_frame.pack(fill="both", expand=True, padx=15, pady=8)
        tree = ttk.Treeview(tree_frame, columns=("Usuário", "Data", "Hora"), show="headings", style="Custom.Treeview")
        for col, text in [("Usuário", "Usuário"), ("Data", "Data"), ("Hora", "Hora")]: tree.heading(col, text=text)
        tree.pack(side="left", fill="both", expand=True)
        scrollbar = ctk.CTkScrollbar(tree_frame, command=tree.yview, fg_color=COLORS["card"], button_color=COLORS["primary"])
        scrollbar.pack(side="right", fill="y")
        tree.configure(yscrollcommand=scrollbar.set)
        style = ttk.Style()
        style.configure("Custom.Treeview", font=FONTS["label"], rowheight=25, background=COLORS["card"], foreground=COLORS["text"], fieldbackground=COLORS["card"])
        style.configure("Custom.Treeview.Heading", font=FONTS["subtitle"], background=COLORS["border"])
        try:
            _, stdout, _ = client.exec_command("last -w | head -n 20")
            for line in stdout.read().decode().splitlines():
                parts = line.split()
                if len(parts) >= 4: tree.insert("", "end", values=(parts[0], parts[3], parts[4]))
            logging.info("Atividade de usuários listada")
        except Exception as e:
            logging.error(f"Falha ao listar atividade: {e}")
            self._show_message("Erro", f"Falha ao listar: {e}")
        finally:
            client.close()
        self._update_sizes()

    def _export_config(self):
        filename = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if filename:
            try:
                with open(filename, "w") as f: json.dump(self.config, f, indent=4)
                logging.info(f"Configuração exportada para {filename}")
                self._show_message("Sucesso", f"Configuração exportada para {filename}.", "info")
            except Exception as e:
                logging.error(f"Falha ao exportar configuração: {e}")
                self._show_message("Erro", f"Falha ao exportar: {e}")

    def _import_config(self):
        filename = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if filename:
            try:
                with open(filename, "r") as f: config = json.load(f)
                self.connections = [ServerConnection(id=c.get("id", str(uuid.uuid4())), name=c.get("name", f"Servidor {i+1}"),
                                                    ip=c.get("ip", ""), username=c.get("username", ""), save_password=c.get("save_password", False), password=c.get("password"))
                                    for i, c in enumerate(config.get("connections", []))]
                self._update_connections()
                self._save_config()
                if self.connections: self._select_connection(self.connections[0].name)
                logging.info(f"Configuração importada de {filename}")
                self._show_message("Sucesso", f"Configuração importada de {filename}.", "info")
            except Exception as e:
                logging.error(f"Falha ao importar configuração: {e}")
                self._show_message("Erro", f"Falha ao importar: {e}")

    def _execute_custom(self):
        if not self._validate_connection(): return
        cmd, pwd_ssh = self.entry_custom_cmd.get().strip(), self.entry_senha_ssh.get().strip()
        if not cmd: 
            self._show_message("Erro", "Digite um comando.")
            self.entry_custom_cmd.configure(border_color=COLORS["error"])
            return
        client = self._connect_ssh()
        if not client: return
        try:
            channel = client.invoke_shell()
            output = self._execute_sudo(channel, f"sudo -S {cmd}", pwd_ssh)
            channel.close()
            self.custom_output.configure(state="normal")
            self.custom_output.delete("0.0", ctk.END)
            self.custom_output.insert("0.0", output or "Sem saída.")
            self.custom_output.configure(state="disabled")
            logging.info(f"Comando personalizado executado: {cmd}")
            self._show_message("Sucesso", "Comando executado.", "info")
            self.entry_custom_cmd.configure(border_color=COLORS["success"])
        except Exception as e:
            logging.error(f"Falha ao executar comando '{cmd}': {e}")
            self._show_message("Erro", f"Falha ao executar: {e}")
            self.entry_custom_cmd.configure(border_color=COLORS["error"])
        finally:
            client.close()

    def _list_users(self):
        self._clear_content()
        client = self._connect_ssh()
        if not client: return
        card = self._create_card(self.content_frame, "Usuários do Sistema")
        tree_frame = ctk.CTkFrame(card, fg_color="transparent")
        tree_frame.pack(fill="both", expand=True, padx=15, pady=8)
        tree = ttk.Treeview(tree_frame, columns=("Usuário",), show="headings", style="Custom.Treeview")
        tree.heading("Usuário", text="Usuário")
        tree.pack(side="left", fill="both", expand=True)
        scrollbar = ctk.CTkScrollbar(tree_frame, command=tree.yview, fg_color=COLORS["card"], button_color=COLORS["primary"])
        scrollbar.pack(side="right", fill="y")
        tree.configure(yscrollcommand=scrollbar.set)
        style = ttk.Style()
        style.configure("Custom.Treeview", font=FONTS["label"], rowheight=25, background=COLORS["card"], foreground=COLORS["text"], fieldbackground=COLORS["card"])
        style.configure("Custom.Treeview.Heading", font=FONTS["subtitle"], background=COLORS["border"])
        try:
            _, stdout, _ = client.exec_command("getent passwd | grep '/home' | cut -d: -f1")
            for user in stdout.read().decode().splitlines(): tree.insert("", "end", values=(user,))
            logging.info("Usuários listados")
        except Exception as e:
            logging.error(f"Falha ao listar usuários: {e}")
            self._show_message("Erro", f"Falha ao listar: {e}")
        finally:
            client.close()
        self._update_sizes()

    def _check_disk(self):
        self._clear_content()
        client = self._connect_ssh()
        if not client: return
        card = self._create_card(self.content_frame, "Espaço em Disco")
        text_frame = ctk.CTkFrame(card, fg_color="transparent")
        text_frame.pack(fill="both", expand=True, padx=15, pady=8)
        text_area = ctk.CTkTextbox(text_frame, font=FONTS["label"], state="disabled", wrap="none", fg_color=COLORS["background"])
        text_area.pack(side="left", fill="both", expand=True)
        scrollbar = ctk.CTkScrollbar(text_frame, command=text_area.yview, fg_color=COLORS["card"], button_color=COLORS["primary"])
        scrollbar.pack(side="right", fill="y")
        text_area.configure(yscrollcommand=scrollbar.set)
        try:
            _, stdout, _ = client.exec_command("df -h --output=source,fstype,size,used,avail,pcent,target")
            text_area.configure(state="normal")
            text_area.insert("0.0", stdout.read().decode())
            text_area.configure(state="disabled")
            logging.info("Espaço em disco verificado")
        except Exception as e:
            logging.error(f"Falha ao verificar espaço: {e}")
            self._show_message("Erro", f"Falha ao verificar espaço: {e}")
        finally:
            client.close()
        self._update_sizes()

    def _reset_password(self):
        self._clear_content()
        card = self._create_card(self.content_frame, "Resetar Senha")
        form_frame = ctk.CTkFrame(card, fg_color="transparent")
        form_frame.pack(fill="x", padx=15, pady=8)
        self.entry_user = self._create_entry(form_frame, "Usuário", "Digite o nome do usuário", attr="entry_user")
        self.entry_new_pass = self._create_entry(form_frame, "Nova Senha", "Digite a nova senha", show="*", attr="entry_new_pass")
        self._create_button(form_frame, "Resetar", lambda: self._run_thread(self._do_reset_password), COLORS["primary"], COLORS["secondary"], padx=10)

    def _do_reset_password(self):
        username, new_pass, pwd_ssh = self.entry_user.get().strip(), self.entry_new_pass.get().strip(), self.entry_senha_ssh.get().strip()
        if not all([username, new_pass]):
            self._show_message("Erro", "Preencha todos os campos.")
            for e, v in [(self.entry_user, username), (self.entry_new_pass, new_pass)]: e.configure(border_color=COLORS["error"] if not v else COLORS["border"])
            return
        if not re.match(r"^[a-z][a-z0-9_-]{2,15}$", username):
            self._show_message("Erro", "Nome inválido.")
            self.entry_user.configure(border_color=COLORS["error"])
            return
        client = self._connect_ssh()
        if not client: return
        try:
            channel = client.invoke_shell()
            for cmd, input_, _ in [(f"sudo -S chpasswd", f"{username}:{new_pass}\n", "Erro ao resetar senha"),
                                   (f"sudo -S smbpasswd -a {username}", f"{new_pass}\n{new_pass}\n", "Erro ao configurar Samba")]:
                self._execute_sudo(channel, cmd, pwd_ssh, input_)
            channel.close()
            logging.info(f"Senha resetada: {username}")
            self._show_message("Sucesso", f"Senha resetada: {username}", "info")
            for e in [self.entry_user, self.entry_new_pass]: e.configure(border_color=COLORS["success"])
        except Exception as e:
            logging.error(f"Falha ao resetar senha: {e}")
            self._show_message("Erro", f"Falha ao resetar: {e}")
            for e in [self.entry_user, self.entry_new_pass]: e.configure(border_color=COLORS["error"])
        finally:
            client.close()

    def _test_connection(self):
        self._clear_content()
        card = self._create_card(self.content_frame, "Testar Conexão")
        client = self._connect_ssh()
        status = "Conexão estabelecida!" if client else "Falha na conexão."
        ctk.CTkLabel(card, text=status, font=FONTS["subtitle"], text_color=COLORS["success" if client else "error"]).pack(pady=15)
        if client:
            logging.info("Teste de conexão bem-sucedido")
            client.close()

    def _show_history(self):
        self._clear_content()
        card = self._create_card(self.content_frame, "Histórico de Operações")
        text_frame = ctk.CTkFrame(card, fg_color="transparent")
        text_frame.pack(fill="both", expand=True, padx=15, pady=8)
        text_area = ctk.CTkTextbox(text_frame, font=FONTS["label"], state="disabled", wrap="none", fg_color=COLORS["background"])
        text_area.pack(side="left", fill="both", expand=True)
        scrollbar = ctk.CTkScrollbar(text_frame, command=text_area.yview, fg_color=COLORS["card"], button_color=COLORS["primary"])
        scrollbar.pack(side="right", fill="y")
        text_area.configure(yscrollcommand=scrollbar.set)
        try:
            with open(LOG_FILE, "r") as log:
                text_area.configure(state="normal")
                text_area.insert("0.0", log.read() or "Nenhum histórico.")
            logging.info("Histórico exibido")
        except FileNotFoundError:
            text_area.configure(state="normal")
            text_area.insert("0.0", "Nenhum histórico.")
        text_area.configure(state="disabled")
        self._update_sizes()

    def setup_ui(self):
        if not self.logged_in:
            self._show_login()
        else:
            self._show_main()

    def run(self):
        self.app.mainloop()

if __name__ == "__main__":
    UserManagerApp().run()

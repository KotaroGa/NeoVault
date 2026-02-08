"""
Matrix-style GUI for NeoVault.
Green/black terminal-like interface.
"""
import customtkinter as ctk
from typing import Optional, Callable
import sys
import os

# Import controllers
from .controllers import (
    VaultController,
    PasswordGeneratorController,
    SearchController,
    SystemController
)


# Add path to import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))



class MatrixGUI:
    """Main Matrix-style GUI window"""


    def __init__(self):
        # Configure Matrix theme (green on black)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")

        self.root = ctk.CTk()
        self.root.title("🔐 NeoVault - MATRIX MODE")
        self.root.geometry("900x600")

        # Initialize controllers
        self.vault_controller = VaultController()
        self.generator_controller = PasswordGeneratorController()
        self.search_controller = SearchController()
        self.system_controller = SystemController()

        # Style configuration
        self._setup_matrix_theme()
        self._create_widgets()

        # Update status with system info
        self._update_status()

    

    def _setup_matrix_theme(self):
        "Configure Matrix green/black theme"
        self.matrix_green = "#00FF41"
        self.matrix_dark = "#0A0A0A"
        self.matrix_darker = "#050505"


    def _clear_content(self):
        """Clear all widgets from content frame"""
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()


    def _create_widgets(self):
        """Create main GUI widget"""
        self.main_frame = ctk.CTkFrame(
            self.root,
            fg_color=self.matrix_darker,
            corner_radius=0
        )
        self.main_frame.pack(fill="both", expand=True, padx=2, pady=2)

        self._create_sidebar()

        self._create_main_area()

        self._create_status_bar()



    def _create_sidebar(self):
        """Create terminal-like sidebar"""
        sidebar = ctk.CTkFrame(
            self.main_frame,
            width=200,
            fg_color=self.matrix_dark,
            corner_radius=0
        )
        sidebar.pack(side="left", fill="y", padx=(0, 2), pady=2)
        sidebar.pack_propagate(False)

        title = ctk.CTkLabel(
            sidebar,
            text=">_ NEOVAULT SYSTEM",
            font=("Consolas", 14, "bold"),
            text_color=self.matrix_green
        )
        title.pack(pady=(20, 10))

        # Add vault count to button
        vault_stats = self.vault_controller.get_vault_stats()
        vault_count = vault_stats["total_vaults"]
        
        buttons = [
            (f"📁 VAULTS ({vault_count})", self._show_vaults),
            ("🔍 SEARCH", self._show_search),
            ("🔑 GENERATE", self._show_generator),
            ("⚙️ SETTINGS", self._show_settings),
            ("🖥️ TERMINAL", self._show_terminal),
        ]

        for text, command in buttons:
            btn = ctk.CTkButton(
                sidebar,
                text=text,
                font=("Consolas", 12),
                fg_color="transparent",
                hover_color="#003310",
                text_color=self.matrix_green,
                border_color=self.matrix_green,
                border_width=1,
                corner_radius=0,
                command=command
            )
            btn.pack(pady=5, padx=10, fill="x")



    def _create_main_area(self):
        """Create main content area"""
        self.content_frame = ctk.CTkFrame(
            self.main_frame,
            fg_color=self.matrix_dark
        )
        self.content_frame.pack(side="top", fill="both", expand=True, padx=2, pady=2)
    
        # Frame para el contenido dinámico (arriba)
        self.dynamic_frame = ctk.CTkFrame(
            self.content_frame,
            fg_color="transparent"
        )
        self.dynamic_frame.pack(fill="both", expand=True, padx=2, pady=2)
    
        # Frame para el terminal (abajo)
        terminal_frame = ctk.CTkFrame(
            self.content_frame,
            fg_color="transparent",
            height=150
        )
        terminal_frame.pack(side="bottom", fill="x", padx=2, pady=(0, 2))
        terminal_frame.pack_propagate(False)
    
        # Terminal header
        term_header = ctk.CTkLabel(
            terminal_frame,
            text=">_ SYSTEM TERMINAL",
            font=("Consolas", 11, "bold"),
            text_color=self.matrix_green
        )
        term_header.pack(anchor="w", padx=5, pady=(5, 0))
    
        # Terminal textbox
        self.terminal_text = ctk.CTkTextbox(
            terminal_frame,
            font=("Consolas", 10),
            fg_color="black",
            text_color=self.matrix_green,
            border_color=self.matrix_green,
            border_width=1,
            corner_radius=0
        )
        self.terminal_text.pack(fill="both", expand=True, padx=5, pady=5)
    
        welcome_msg = """
>_ SYSTEM: NEOVAULT v0.4.0 ONLINE
>_ MODE: MATRIX INTERFACE
>_ STATUS: GUI OPERATIONAL
>_ COMMANDS: TYPE 'help' FOR OPTIONS

>_ READY FOR USER INPUT...
"""
        self.terminal_text.insert("1.0", welcome_msg)
        self.terminal_text.configure(state="disabled")



    def _create_status_bar(self):
        """Create Matrix-style status bar"""
        status_frame = ctk.CTkFrame(
            self.root,
            height=30,
            fg_color=self.matrix_darker,
            corner_radius=0
        )
        status_frame.pack(side="bottom", fill="x")
        status_frame.pack_propagate(False)

        self.status_label = ctk.CTkLabel(
            status_frame,
            text=">_ SYSTEM: INITIALIZING...",
            font=("Consolas", 10),
            text_color=self.matrix_green
        )
        self.status_label.pack(side="left", padx=10)

        # FPS counter (placeholder)
        fps_label = ctk.CTkLabel(
            status_frame,
            text="FPS: 60 | MEM: --",
            font=("Consolas", 9),
            text_color=self.matrix_green
        )
        fps_label.pack(side="right", padx=10)
        
        # Actualizar con información real
        self._update_status()



    def _show_vaults(self):
        """Show vault manager using controller"""
        self._clear_content()
        
        # Get vault stats
        stats = self.vault_controller.get_vault_stats()
        
        # Header
        header = ctk.CTkLabel(
            self.dynamic_frame,
            text=f">_ VAULT MANAGER ({stats['total_vaults']} vaults)",
            font=("Consolas", 16, "bold"),
            text_color=self.matrix_green
        )
        header.pack(pady=(20, 10))

        # Control buttons frame
        control_frame = ctk.CTkFrame(
            self.dynamic_frame,
            fg_color="transparent"
        )
        control_frame.pack(fill="x", padx=20, pady=10)

        # Create vault button
        create_btn = ctk.CTkButton(
            control_frame,
            text="+ CREATE VAULT",
            font=("Consolas", 12),
            fg_color="transparent",
            hover_color="#003310",
            text_color=self.matrix_green,
            border_color=self.matrix_green,
            border_width=1,
            command=self._open_create_vault_dialog
        )
        create_btn.pack(side="left", padx=5)

        # Load vault button
        load_btn = ctk.CTkButton(
            control_frame,
            text="📁 LOAD VAULT",
            font=("Consolas", 12),
            fg_color="transparent",
            hover_color="#003310",
            text_color=self.matrix_green,
            border_color=self.matrix_green,
            border_width=1,
            command=self._open_load_vault_dialog
        )
        load_btn.pack(side="left", padx=5)

        # Refresh button
        refresh_btn = ctk.CTkButton(
            control_frame,
            text="🔄 REFRESH",
            font=("Consolas", 12),
            fg_color="transparent",
            hover_color="#003310",
            text_color=self.matrix_green,
            border_color=self.matrix_green,
            border_width=1,
            command=self._show_vaults
        )
        refresh_btn.pack(side="right", padx=5)

        # Vaults list frame
        list_frame = ctk.CTkFrame(
            self.dynamic_frame,
            fg_color=self.matrix_dark
        )
        list_frame.pack(fill="both", expand=True, padx=20, pady=10)

        if stats["total_vaults"] > 0:
            # Show vaults list
            list_label = ctk.CTkLabel(
                list_frame,
                text="AVAILABLE VAULTS:",
                font=("Consolas", 12, "bold"),
                text_color=self.matrix_green
            )
            list_label.pack(anchor="w", padx=10, pady=(10, 5))

            for i, vault_file in enumerate(stats["vaults_list"]):
                vault_text = ctk.CTkLabel(
                    list_frame,
                    text=f"  [{i+1}] {vault_file}",
                    font=("Consolas", 11),
                    text_color=self.matrix_green
                )
                vault_text.pack(anchor="w", padx=20, pady=2)
        else:
            # No vaults message
            no_vaults = ctk.CTkLabel(
                list_frame,
                text=">_ No vaults found.\n>_ Create a new vault to get started.",
                font=("Consolas", 11),
                text_color=self.matrix_green
            )
            no_vaults.pack(pady=20)

        # Update terminal
        self._update_terminal(f">_ VAULT MANAGER: Showing {stats['total_vaults']} vaults")



    def _open_create_vault_dialog(self):
        """Open dialog to create new vault"""
        self._update_terminal(">_ CREATE VAULT: Opening dialog...")
        # Placeholder - will implement dialog
        self._show_simple_dialog("Create Vault", "Vault creation dialog will be implemented soon")

    def _open_load_vault_dialog(self):
        """Open dialog to load existing vault"""
        self._update_terminal(">_ LOAD VAULT: Opening dialog...")
        # Placeholder - will implement dialog
        self._show_simple_dialog("Load Vault", "Vault loading dialog will be implemented soon")

    def _show_search(self):
        self._update_terminal(">_ SEARCH INTERFACE ACTIVATED...")



    def _show_generator(self):
        """Show password generator using controller"""
        self._clear_content()
        
        # Header
        header = ctk.CTkLabel(
            self.dynamic_frame,
            text=">_ PASSWORD GENERATOR",
            font=("Consolas", 16, "bold"),
            text_color=self.matrix_green
        )
        header.pack(pady=(20, 10))

        # Generate a sample password
        result = self.generator_controller.generate_password()
        
        # Password display
        password_frame = ctk.CTkFrame(
            self.dynamic_frame,
            fg_color=self.matrix_dark,
            height=80
        )
        password_frame.pack(fill="x", padx=20, pady=10)
        password_frame.pack_propagate(False)

        password_label = ctk.CTkLabel(
            password_frame,
            text="GENERATED PASSWORD:",
            font=("Consolas", 12, "bold"),
            text_color=self.matrix_green
        )
        password_label.pack(anchor="w", padx=10, pady=(10, 5))

        password_display = ctk.CTkLabel(
            password_frame,
            text=result["password"],
            font=("Consolas", 14, "bold"),
            text_color=self.matrix_green
        )
        password_display.pack(pady=5)

        # Strength indicator
        strength_color = "#00FF00" if result["strength"] >= 60 else "#FFFF00" if result["strength"] >= 40 else "#FF0000"
        strength_text = ctk.CTkLabel(
            password_frame,
            text=f"Strength: {result['strength_text']} ({result['strength']}/100)",
            font=("Consolas", 10),
            text_color=strength_color
        )
        strength_text.pack(pady=(0, 10))

        # Control buttons
        button_frame = ctk.CTkFrame(
            self.dynamic_frame,
            fg_color="transparent"
        )
        button_frame.pack(fill="x", padx=20, pady=10)

        # Generate button
        gen_btn = ctk.CTkButton(
            button_frame,
            text="🔄 GENERATE NEW",
            font=("Consolas", 12),
            fg_color="transparent",
            hover_color="#003310",
            text_color=self.matrix_green,
            border_color=self.matrix_green,
            border_width=1,
            command=self._show_generator
        )
        gen_btn.pack(side="left", padx=5)

        # Copy button
        copy_btn = ctk.CTkButton(
            button_frame,
            text="📋 COPY TO CLIPBOARD",
            font=("Consolas", 12),
            fg_color="transparent",
            hover_color="#003310",
            text_color=self.matrix_green,
            border_color=self.matrix_green,
            border_width=1,
            command=lambda: self._copy_to_clipboard(result["password"])
        )
        copy_btn.pack(side="left", padx=5)

        # Info text
        info_text = ctk.CTkLabel(
            self.dynamic_frame,
            text=f">_ Length: {result['length']} chars\n>_ Categories: {', '.join(result['categories'])}",
            font=("Consolas", 10),
            text_color=self.matrix_green
        )
        info_text.pack(pady=10)

        # Update terminal
        self._update_terminal(f">_ PASSWORD GENERATOR: Generated {result['length']}-char password ({result['strength_text']})")



    def _copy_to_clipboard(self, text: str):
        """Copy text to clipboard"""
        try:
            import pyperclip
            pyperclip.copy(text)
            self._update_terminal(">_ CLIPBOARD: Password copied successfully")
        except ImportError:
            self._update_terminal(">_ ERROR: pyperclip not installed")



    def _show_settings(self):
        self._update_terminal(">_ SYSTEM SETTINGS ACCESSED...")

    def _show_terminal(self):
        self._update_terminal(">_ TERMINAL MODE ENGADED...")

    def _update_terminal(self, message: str):
        """Update terminal display with new message"""
        self.terminal_text.configure(state="normal")
        self.terminal_text.insert("end", f"\n{message}")
        self.terminal_text.see("end")
        self.terminal_text.configure(state="disabled")



    def _show_simple_dialog(self, title: str, message: str):
        """Show a simple informational dialog"""
        # Usar after para asegurar que la ventana esté lista
        self.root.after(100, lambda: self._create_dialog(title, message))
    

    
    def _create_dialog(self, title: str, message: str):
        """Create the dialog (called after delay)"""
        dialog = ctk.CTkToplevel(self.root)
        dialog.title(title)
        dialog.geometry("400x200")
        dialog.transient(self.root)
        
        # Centrar el diálogo
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (400 // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (200 // 2)
        dialog.geometry(f"+{x}+{y}")
        
        dialog.grab_set()

        label = ctk.CTkLabel(
            dialog,
            text=message,
            font=("Consolas", 12),
            text_color=self.matrix_green
        )
        label.pack(pady=40)

        ok_btn = ctk.CTkButton(
            dialog,
            text="OK",
            command=dialog.destroy
        )
        ok_btn.pack(pady=10)



    def _update_status(self):
        """Update status bar with system info"""
        try:
            sys_info = self.system_controller.get_system_info()
            status_text = f">_ SYSTEM: {sys_info['platform']} | MEM: {sys_info['memory_used']:.1f}% | CPU: {sys_info['cpu_usage']:.1f}%"
            self.status_label.configure(text=status_text)
        except Exception:
            self.status_label.configure(text=">_ SYSTEM: STATUS UNAVAILABLE")



    def run(self):
        """Start the GUI application"""
        self.root.mainloop()



def main():
    """Entry point for GUI application"""
    app = MatrixGUI()
    app.run()


if __name__ == "__main__":
    main()

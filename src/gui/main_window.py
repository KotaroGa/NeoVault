"""
Matrix-style GUI for NeoVault.
Green/black terminal-like interface.
"""
import customtkinter as ctk
from typing import Optional, Callable
import sys
import os

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

        # Style configuration
        self._setup_matrix_theme()
        self._create_widgets()

    

    def _setup_matrix_theme(self):
        "Configure Matrix green/black theme"
        self.matrix_green = "#00FF41"
        self.matrix_dark = "#0A0A0A"
        self.matrix_darker = "#050505"



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

        buttons = [
            ("📁 VAULTS", self._show_vaults),
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
                hover_color="#00FF41",
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
        self.content_frame.pack(side="right", fill="both", expand=True, padx=2, pady=2)

        header = ctk.CTkLabel(
            self.content_frame,
            text=">_ MATRIX INTERFACE ACTIVE",
            font=("Consolas", 16, "bold"),
            text_color=self.matrix_green
        )
        header.pack(pady=(20, 10))

        self.terminal_text = ctk.CTkTextbox(
            self.content_frame,
            font=("Consolas", 11),
            fg_color="black",
            text_color=self.matrix_green,
            border_color=self.matrix_green,
            border_width=1,
            corner_radius=0
        )
        self.terminal_text.pack(fill="both", expand=True, padx=20, pady=10)


        welcome_msg = """
>_ SYSTEM: NEOVAULT v0.4.0 ONLINE
>_ MODE: MATRIX INTERFACE
>_ STATUS: GUI OPERATIONAL
>_ COMMANDS: TYPE 'help' FOR OPTIONS

>_ VAULTS: 0 LOADED
>_ ENTRIES: 0 PROTECTED
>_ SECURITY: AES-256-GCM ACTIVE

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
            text=">_ SYSTEM: GUI ACTIVE | MODE: MATRIX | READY",
            font=("Consolas", 10),
            text_color=self.matrix_green
        )
        self.status_label.pack(side="left", padx=10)

        # FPS counter
        fps_label = ctk.CTkLabel(
            status_frame,
            text="FPS: 60 | MEM: 12.4MB",
            font=("Consolas", 9),
            text_color=self.matrix_green
        )
        fps_label.pack(side="right", padx=10)


    # Placeholder buttons
    def _show_vaults(self):
        self._update_terminal(">_ LOADING VAULT BROWSER...")

    def _show_search(self):
        self._update_terminal(">_ SEARCH INTERFACE ACTIVATED...")

    def _show_generator(self):
        self._update_terminal(">_ PASSWORD GENERATOR ONLINE...")

    def _show_settings(self):
        self._update_terminal(">_ SYSTEM SETTINGS ACCESSED...")

    def _show_terminal(self):
        self._update_terminal(">_ TERMINAL MODE ENGADED...")

    def _update_terminal(self, message: str):
        """Update terminal display with new message"""
        self.terminal_text.configure(state="normal")
        self.terminal_text.insert("end", f"\n{message}")
        self.terminal_text.see("end")
        self.terminal_text.configure(state="disable")

    def run(self):
        """Start the GUI application"""
        self.root.mainloop()



def main():
    """Entry point for GUI application"""
    app = MatrixGUI()
    app.run()


if __name__ == "__main__":
    main()

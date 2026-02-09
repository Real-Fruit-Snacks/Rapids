"""Catppuccin Mocha color theme for Rapids."""

from rich.theme import Theme

# Catppuccin Mocha palette
MOCHA = {
    "rosewater": "#f5e0dc",
    "flamingo": "#f2cdcd",
    "pink": "#f5c2e7",
    "mauve": "#cba6f7",
    "red": "#f38ba8",
    "maroon": "#eba0ac",
    "peach": "#fab387",
    "yellow": "#f9e2af",
    "green": "#a6e3a1",
    "teal": "#94e2d5",
    "sky": "#89dceb",
    "sapphire": "#74c7ec",
    "blue": "#89b4fa",
    "lavender": "#b4befe",
    "text": "#cdd6f4",
    "subtext1": "#bac2de",
    "subtext0": "#a6adc8",
    "overlay2": "#9399b2",
    "overlay1": "#7f849c",
    "overlay0": "#6c7086",
    "surface2": "#585b70",
    "surface1": "#45475a",
    "surface0": "#313244",
    "base": "#1e1e2e",
    "mantle": "#181825",
    "crust": "#11111b",
}

# Semantic mapping for Rapids
RAPIDS_THEME = Theme({
    # Status colors
    "success": f"bold {MOCHA['green']}",
    "failure": MOCHA["red"],
    "error": MOCHA["peach"],
    "timeout": MOCHA["yellow"],

    # UI elements
    "banner": f"bold {MOCHA['mauve']}",
    "banner.sub": MOCHA["overlay1"],
    "heading": f"bold {MOCHA['lavender']}",
    "label": MOCHA["sapphire"],
    "value": MOCHA["text"],
    "warn": MOCHA["yellow"],
    "info": MOCHA["sky"],
    "dim": MOCHA["overlay0"],
    "hit": f"bold {MOCHA['green']}",
    "hit.cred": MOCHA["teal"],

    # Table
    "table.header": f"bold {MOCHA['lavender']}",
    "table.service": MOCHA["sapphire"],
    "table.target": MOCHA["text"],
    "table.user": MOCHA["flamingo"],
    "table.pass": MOCHA["rosewater"],
    "table.msg": MOCHA["subtext0"],

    # Progress bar
    "progress.description": MOCHA["blue"],
    "progress.percentage": MOCHA["mauve"],
    "bar.complete": MOCHA["green"],
    "bar.finished": MOCHA["green"],
    "bar.pulse": MOCHA["mauve"],
})

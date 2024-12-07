from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

# Mensaje de bienvenida con un panel
console.print(Panel("[bold green]Bienvenido a Mensajería Privada[/bold green]"))

# Crear una tabla para mostrar mensajes
table = Table(title="Mensajes Recibidos")
table.add_column("Usuario", style="cyan", justify="left")
table.add_column("Mensaje", style="magenta")
table.add_column("Fecha", justify="right")

# Agregar filas
table.add_row("Juan", "Hola, ¿cómo estás?", "2024-12-05")
table.add_row("María", "Gracias por el mensaje", "2024-12-04")

# Mostrar la tabla
console.print(table)


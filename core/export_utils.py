"""
Reusable result-export helper. Any tool with a QTableWidget of results
can add a one-line "Export to CSV" button using export_table_to_csv()
instead of reimplementing file-save logic per tool.
"""
import csv
from PyQt6.QtWidgets import QFileDialog, QTableWidget


def export_table_to_csv(parent_widget, table: QTableWidget, default_filename: str) -> str | None:
    """
    Prompts the user for a save location and writes the given table's
    contents (headers + all rows) to CSV. Returns the saved path, or
    None if the user cancelled or the table was empty.
    """
    if table.rowCount() == 0:
        return None

    path, _ = QFileDialog.getSaveFileName(
        parent_widget, "Export results as CSV", default_filename, "CSV Files (*.csv)"
    )
    if not path:
        return None

    headers = [table.horizontalHeaderItem(col).text() if table.horizontalHeaderItem(col) else ""
               for col in range(table.columnCount())]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for row in range(table.rowCount()):
            row_data = []
            for col in range(table.columnCount()):
                item = table.item(row, col)
                row_data.append(item.text() if item else "")
            writer.writerow(row_data)

    return path


def export_text_to_file(parent_widget, text: str, default_filename: str,
                         file_filter: str = "Text Files (*.txt)") -> str | None:
    """Same idea, for tools whose results are free-form text rather than a table."""
    if not text.strip():
        return None

    path, _ = QFileDialog.getSaveFileName(parent_widget, "Export results", default_filename, file_filter)
    if not path:
        return None

    with open(path, "w", encoding="utf-8") as f:
        f.write(text)

    return path

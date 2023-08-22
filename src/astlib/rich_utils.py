import pandas as pd
from rich.table import Table
from typing import Dict

def df_to_richtable(df:pd.DataFrame, title:str, rowstyle='default',
    colwidths={},
    row_idx_to_style:Dict[int,str]=None,
    header_style='default',
    title_style='default') -> Table:
    table = Table(title=title, header_style=header_style, title_style=title_style)
    rows = df.values.tolist()
    rows = [[str(el) for el in row] for row in rows]
    columns = df.columns.tolist()

    for column in columns:
        if column in colwidths:
            table.add_column(column, width=colwidths[column])
        else:
            table.add_column(column)

    for i, row in enumerate(rows):
        style = rowstyle
        if row_idx_to_style and i in row_idx_to_style:
            style = row_idx_to_style[i]
        table.add_row(*row, style=style)

    return table

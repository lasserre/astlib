import argparse
import json
import os
import pandas as pd
from pathlib import Path
from rich.console import Console
from rich.table import Table

from ..rich_utils import df_to_richtable

# check the logs across an entire AST export folder and report a tabular summary
# of the status

# > right now, I primarily want a summary of unimplemented ops/code to use
#   as a todo list and a status report of roughly how much AST is unimplemented
# > later this would be a useful validation step to run post-export once I
#   THINK I have everything exported correctly...(in addition to a proper validation)

CONFIG_FILE_ENVVAR = 'GHIDRA_AST_CONFIG_FILE'

def report_ast_export(args):

    # maybe just do everything based on the env var for now?
    configfile = Path(os.environ[CONFIG_FILE_ENVVAR]) if CONFIG_FILE_ENVVAR in os.environ else None
    if not configfile:
        print(f'No config file set in {CONFIG_FILE_ENVVAR}')
        return 1

    with open(configfile, 'r') as f:
        config = json.load(f)

    exportfolder = Path(config['output_folder'])
    jsonfiles = list(exportfolder.glob('*.json'))
    logfiles = list(exportfolder.glob('*.log'))

    stats = {
        'Function': [],
        'Item': []
    }

    for log in logfiles:
        with open(log, 'r') as f:
            for l in [x for x in f.readlines() if '[todo]' in x]:
                line = l.strip()
                stats['Function'].append(log.stem)
                stats['Item'].append(line)

    df = pd.DataFrame.from_dict(stats)

    item_counts = df.groupby('Item').count()
    item_counts.columns = ['Count']
    item_counts = item_counts.reset_index().sort_values('Count',ascending=False)

    fcount = df.groupby('Function').count()
    funique = df.groupby('Function').nunique()
    fcount.columns = ['Total']
    funique.columns = ['Unique']
    func_counts = fcount.join(funique, on='Function') \
        .reset_index()

    jset = set(jf.stem for jf in jsonfiles)
    lset = set(lf.stem for lf in logfiles)

    # jset - lset => functions that passed with no errors (thus no log file)
    for func_success in jset.difference(lset):
        # there were no errors here - add row manually
        func_counts.loc[len(func_counts)] = {
            'Function': func_success,
            'Total': 0,
            'Unique': 0,
        }

    func_counts = func_counts.sort_values('Total', ascending=False)

    # import IPython; IPython.embed()

    console = Console()

    ##### Summary table
    total_funcs = len(func_counts)
    no_fails = len(func_counts[func_counts.Total==0])
    num_fails = len(func_counts) - no_fails

    t = Table(title="Summary")
    t.add_column("Category")#, justify="right", style="cyan", no_wrap=True)
    t.add_column("Number of Funcs")#, style="magenta")
    t.add_column("Percentage", style='bold')#, justify="right", style="green")

    t.add_row('Total exported functions', f'{total_funcs}', f'{100:.2f}%' if total_funcs else '-')
    pass_style = 'green' if no_fails else 'default'
    t.add_row('No Failures', f'{no_fails}', f'{no_fails/total_funcs*100:.2f}%' if total_funcs else '-', style=pass_style)
    fail_style = 'red' if num_fails else 'default'
    t.add_row('Had Failures', f'{num_fails}', f'{num_fails/total_funcs*100:.2f}%' if total_funcs else '-', style=fail_style)

    console.print(t)

    ##### Item counts
    item_limit = 15
    console.print()
    console.print(f'{len(item_counts)} unimplemented AST items remain', style='yellow italic')
    console.print()

    table = df_to_richtable(item_counts[:item_limit],
        f'Failure List (top {item_limit} unimplemented items)',
        rowstyle='bright_yellow')
    console.print(table)

    ##### Function counts
    func_limit = 10
    table = df_to_richtable(func_counts[:func_limit],
        f"Function Counts (top {func_limit} with most failures)",
        rowstyle='bright_green',
        colwidths={'Function': 55})
    console.print(table)

    return 0

def main():
    p = argparse.ArgumentParser(
        description='Check the logs across an entire AST export folder and report status')
    args = p.parse_args()
    exit(report_ast_export(args))

if __name__ == '__main__':
    main()

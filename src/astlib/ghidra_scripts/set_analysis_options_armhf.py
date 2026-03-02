#Set analysis options
#@author Caleb Stewart
#@category phd
#@keybinding
#@menupath
#@toolbar

# this try/except construction makes intellisense nice with ghidra type stubs
# installed :)
# https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator

import ghidra
try:
    from ghidra.ghidra_builtins import *
except:
    pass

dwarf_debug_item_limit = int(1e9)   # 1 billion - effectively no limit :)

setAnalysisOption(currentProgram, 'DWARF.Debug Item Limit', str(dwarf_debug_item_limit))
print('Set DWARF.Debug Item Limit to {:,}'.format(dwarf_debug_item_limit))

# CLS: this worked from the GUI python console...
DECOMPILE_TIMEOUT_SEC = 240         # 4 min
setAnalysisOption(currentProgram, 'Decompiler Parameter ID', 'True')
setAnalysisOption(currentProgram, 'Decompiler Parameter ID.Analysis Decompiler Timeout (sec)', str(DECOMPILE_TIMEOUT_SEC))
print('Enabled Decompiler Parameter ID')
print('Set Decompiler Parameter ID.Analysis Decompiler Timeout (sec) to {:,}'.format(DECOMPILE_TIMEOUT_SEC))

# CLS: some of the ARM 32-bit O0 binaries never import without these turned off
setAnalysisOption(currentProgram, 'ARM Constant Reference Analyzer', 'False')
setAnalysisOption(currentProgram, 'Data Reference', 'False')
print('Disabled ARM Constant Reference Analyzer')
print('Disabled Data Reference')

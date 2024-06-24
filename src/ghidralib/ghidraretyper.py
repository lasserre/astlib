import typing
if typing.TYPE_CHECKING:
    import ghidra
    from ghidra.ghidra_builtins import *

# CLS: this should only be imported if pyhidra has been started

# ghidra imports
from ghidra.program.model.listing import Program, FunctionManager
from ghidra.program.model.listing import Function

from ghidra.program.model.address import AddressFactory

from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface

from ghidra.program.model.data import DataType
from ghidra.program.model.data import FunctionDefinitionDataType
from ghidra.program.model.data import StructureDataType
from ghidra.program.model.data import UnionDataType
from ghidra.program.model.data import PointerDataType
from ghidra.program.model.data import ArrayDataType
from ghidra.program.model.data import DataTypeManager
from ghidra.program.model.data import CategoryPath
from ghidra.program.model.data import BuiltInDataTypeManager
from ghidra.program.model.data import DataTypeConflictHandler

from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.pcode import HighSymbol

from ghidra.program.model.symbol import SourceType

# Caleb's stuff (astlib)
from varlib import datatype, StructDatabase

# Normal python stuff
from typing import Dict

# Dictionary to map Caleb's (common) builtin data type strings to Ghidra data type paths
ghidra_data_type_by_caleb_data_type = {
    'void'          :   '/void',
    'float'         :   '/float',
    'double'        :   '/double',
    'long double'   :   '/float10',
    'uchar'         :   '/uchar',
    'ushort'        :   '/ushort',
    'uint32'        :   '/uint',
    'uint64'        :   '/ulonglong',
    # 'uint128'     :   '?',
    # 'uint256'     :   '?',
    # 'uint512'     :   '?',
    'char'          :   '/char',
    'short'         :   '/short',
    'int32'         :   '/int',
    'int64'         :   '/longlong',
    'int128'        :   '/int16'
}

class GhidraRetyper:
    def __init__(self, program:Program, reference_db:StructDatabase) -> None:
        # Save appropriate context information
        self.program = program
        self.function_manager = program.getFunctionManager()
        self.data_type_manager = program.getDataTypeManager()

        # Setup Decompiler Interface
        options = DecompileOptions()
        self.decomp_interface = DecompInterface()
        self.decomp_interface.setOptions(options)
        self.decomp_interface.openProgram(self.program)   # TODO: Error handling

        # Import composite data type database
        self.reference_db = reference_db

        # Define data type Category Paths
        self.struct_category_path = CategoryPath('/GhidraRetyper/Structs')
        self.union_category_path = CategoryPath('/GhidraRetyper/Unions')
        self.func_category_path = CategoryPath('/GhidraRetyper/Funcs')

    def is_conflict(self, sid, comps):
        # Identify explicit conflict definitions
        if '.conflict' in comps[sid].name:
            return True
        # Identify non-explicit conflicts by determining if name appears more than once
        occurrences = [id for id, comp in comps.items() if comp.name == comps[sid].name]
        if len(occurrences) > 1:
            return True
        # Otherwise, no conflicts
        return False

    def check_conflicts(self, structs:Dict[int, datatype.StructDefinition], unions:Dict[int, datatype.UnionDefinition]):
        # Determine if there are any type conflicts
        struct_conflicts = [sid for sid in structs.keys() if self.is_conflict(sid, structs)]
        union_conflicts = [sid for sid in unions.keys() if self.is_conflict(sid, unions)]
        # Return true if any conflicts exist
        return (len(struct_conflicts) +  len(union_conflicts)) > 0

    # TODO: this is a long function, need to break it up
    def define_all_reference_types(self, overwrite_existing:bool=False):
        # Get list of structs and unions by sid for composite type identification
        structs = self.reference_db.structs_by_id
        unions = self.reference_db.unions_by_id
        # Check for conflicts
        if self.check_conflicts(structs, unions) == True:
            raise Exception('ERROR: multiple definitions for the same composite')
        # Iterate through all composites and create empty structs/unions
        for sid in structs | unions:
            # Define empty struct
            if sid in structs.keys():
                stype = structs[sid]
                new_struct = StructureDataType(self.struct_category_path, stype.name, 0)
                self.add_to_data_type_manager(new_struct, None)
            # Define empty union
            elif sid in unions.keys():
                utype = unions[sid]
                new_union = UnionDataType(self.union_category_path, utype.name)
                self.add_to_data_type_manager(new_union, overwrite_existing)
            # Something went wrong and sid not found (should never happen)
            else:
                raise Exception(f'ERROR: {sid} not in structure or union keys')
        # Iterate through composites again and add definitions
        for sid in structs | unions:
            # Define internal struct members
            if sid in structs.keys():
                self.define_struct_type(structs[sid], overwrite_existing)
            # Define internal union members
            elif sid in unions.keys():
                self.define_union_type(unions[sid], overwrite_existing)
            # Something went wrong and sid not found (should never happen)
            else:
                raise Exception(f'ERROR: {sid} not in structure or union keys')

    def add_to_data_type_manager(self, dtype:DataType, overwrite_existing:bool=False):
        # Determine conflict resolution policy
        if overwrite_existing:
            conflict_resolution_policy = DataTypeConflictHandler.REPLACE_HANDLER
        else:
            conflict_resolution_policy = DataTypeConflictHandler.KEEP_HANDLER
        # Add data type to dtm with appropriate conflict resolutin set
        self.data_type_manager.addDataType(dtype, conflict_resolution_policy)

    # TODO: struct and union definitions are very similar
    # Could probably figure out how to shrink these functions down with some common helper functions
    def define_struct_type(self, stype:datatype.StructType, overwrite_existing:bool=False):
        # Get empty struct from data type manager
        ghidra_dtype_path = f'{self.struct_category_path}/{stype.name}'
        new_struct = self.data_type_manager.getDataType(ghidra_dtype_path)
        # Sort fields by offset to ensure correct generation of structure internals
        fields = stype.layout.fields_by_offset.items()
        fields = dict(sorted(fields)).items()
        # Iterate through all fields in dtype structure layout and insert field at correct byte offset
        for offset, details in fields:
            dtype = self.convert_dtype(details.dtype)
            # Skip when the field's data type is undefined (should only be enums now)
            if dtype == None:
                print(f"WARNING: {details.dtype} element of structure (category={details.dtype.category}) not found")
                continue
            # Raise exception when the field's data type is undefined
            if dtype.name == 'void':
                raise Exception(f'ERROR: structure {details.dtype} contains void field')
            # Insert field at byte offset defined in layout
            # Length zero means field length determined from data type size
            new_struct.insertAtOffset(offset, dtype, 0, details.name, None)

    def define_union_type(self, utype:datatype.UnionType, overwrite_existing:bool=False):
        # Get empty union from data type manager
        ghidra_dtype_path = f'{self.union_category_path}/{utype.name}'
        new_union = self.data_type_manager.getDataType(ghidra_dtype_path)
        # Iterate through all fields in union dtype composite and add to empty union
        for details in utype.layout.fields[0]:
            dtype = self.convert_dtype(details.dtype)
            # Skip when the field's data type is undefined (should only be ENUMS now)
            if dtype == None:
                print(f"WARNING: {details.dtype} element of union (category={details.dtype.category}) not found")
                continue
            # Raise exception when the field's data type is undefined
            if dtype.name == 'void':
                raise Exception(f'ERROR: union {details.dtype.name} contains void field')
            # Insert field
            # Length zero means field length determined from data type size
            new_union.add(dtype, 0, details.name, None)

    def set_localvar_type(self, symbol:HighSymbol, dtype:datatype.DataType):
        # Update data type
        ghidra_dtype = self.convert_dtype(dtype)
        # Skip when the field's data type is undefined (should only be enums now)
        if ghidra_dtype == None:
            print(f'WARNING: {symbol.getName()} not updated')
            return
        # This function throws an exception when attempting to update type of unique variable with different size
        HighFunctionDBUtil.updateDBVariable(symbol, None, ghidra_dtype, SourceType.USER_DEFINED)

    def set_globalvar_type(self, global_name:int, global_type:datatype.DataType):
        # do this last: I don't have data for globals right now and we may not need them
        # ...but, while you're doing the others if this is straightforward you can add
        # support for globals too
        pass

    def set_param_type(self, func_addr:int, param_name:str, dtype:datatype.DataType):
        print(f'DYLAN TODO: set decompiler parameter {param_name} in {func_addr:#x} to type {dtype}')

    def set_return_type(self, func_addr:int, dtype:datatype.DataType):
        print(f'DYLAN TODO: set decompiler return type for function {func_addr:#x} to type {dtype}')

    def convert_dtype(self, dtype:datatype.DataType):
        if dtype.category == "BUILTIN":
            ghidra_dtype = self.convert_builtin_dtype(dtype)
        elif dtype.category == "STRUCT":
            ghidra_dtype = self.convert_struct_dtype(dtype)
        elif dtype.category == "UNION":
            ghidra_dtype = self.convert_union_dtype(dtype)
        elif dtype.category == "ARR":
            ghidra_dtype = self.convert_array_dtype(dtype)
        elif dtype.category == "PTR":
            ghidra_dtype = self.convert_pointer_dtype(dtype)
        elif dtype.category == "FUNC":
            ghidra_dtype = self.convert_function_dtype(dtype)
        elif dtype.category == "ENUM":
            ghidra_dtype = None
            # Once this is implemented, can remove the "if dtype == None" case from after each convert call above
            print(f'WARNING: {dtype.category} category not implemented')
        else:
            raise Exception(f'ERROR: {dtype.category} category not recognized')
        # Return ghidra data type from data type manager
        return ghidra_dtype

    def convert_builtin_dtype(self, dtype:datatype.DataType):
        # Generate path and find in builtin dtm
        ghidra_dtype_path = ghidra_data_type_by_caleb_data_type[dtype.standard_name]
        ghidra_dtype = BuiltInDataTypeManager.getDataTypeManager().getDataType(ghidra_dtype_path)
        if ghidra_dtype == None:
            raise Exception(f'ERROR: BUILTIN {dtype.standard_name} not found')
        return ghidra_dtype

    def convert_struct_dtype(self, dtype:datatype.DataType):
        # Generate path and find in program dtm
        ghidra_dtype_path = f'{self.struct_category_path}/{dtype.name}'
        ghidra_dtype = self.data_type_manager.getDataType(ghidra_dtype_path)
        if ghidra_dtype == None:
            raise Exception(f'ERROR: STRUCT {dtype.name} not found')
        return ghidra_dtype

    def convert_union_dtype(self, dtype:datatype.DataType):
        # Generate path and find in program dtm
        ghidra_dtype_path = f'{self.union_category_path}/{dtype.name}'
        ghidra_dtype = self.data_type_manager.getDataType(ghidra_dtype_path)
        if ghidra_dtype == None:
            raise Exception(f'ERROR: UNION {dtype.name} not found')
        return ghidra_dtype

    def convert_array_dtype(self, dtype:datatype.DataType):
        # Convert data type of array element type
        element_type = self.convert_dtype(dtype.element_type)
        if element_type == None:
            raise Exception(f'ERROR: array cannot be created because {dtype.element_type.name} not found')
        ghidra_dtype = ArrayDataType(element_type, dtype.num_elements, 0)
        return ghidra_dtype

    def convert_pointer_dtype(self, dtype:datatype.DataType):
        # Convert data type of pointer element type
        pointed_to_type = self.convert_dtype(dtype.pointed_to)
        if pointed_to_type == None:
            raise Exception(f'ERROR: pointer cannot be created because {dtype.pointed_to.name} not found')
        ghidra_dtype = PointerDataType(pointed_to_type)
        return ghidra_dtype

    def convert_function_dtype(self, dtype:datatype.DataType):
        # For simplicity, try adding function def type to dtm, and don't overwrite existing
        ghidra_dtype = FunctionDefinitionDataType(self.func_category_path, dtype.name)
        self.add_to_data_type_manager(ghidra_dtype, False)
        # Get datatype from dtm
        ghidra_dtype_path = f'{self.func_category_path}/{dtype.name}'
        ghidra_dtype = self.data_type_manager.getDataType(ghidra_dtype_path)
        if ghidra_dtype == None:
            raise Exception(f'ERROR: FUNC {dtype.name} not found')
        return ghidra_dtype

    def get_function_symbols(self, func_addr):
        # Get function from entry point address and return high symbol to name map for functions
        func = self._get_function(func_addr)
        return self._get_symbol_map(func)

    def _get_function(self, func_addr:int):
        # Get function from entry point address
        func_addr = self.program.getAddressFactory().getDefaultAddressSpace().getAddress(func_addr)
        return self.function_manager.getFunctionAt(func_addr)

    def _get_symbol_map(self, func:Function):
        # Decompile function and get high symbols
        res = self.decomp_interface.decompileFunction(func, 60, None)
        high_func = res.getHighFunction()
        if high_func == None:
            raise Exception(f"ERROR: could not decompile {func.name}")
        local_symbol_map = high_func.getLocalSymbolMap()
        # Convert high symbols to name map
        return local_symbol_map.getNameToSymbolMap()
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
from ghidra.program.model.data import DataTypeManager, ProgramBasedDataTypeManager
from ghidra.program.model.data import CategoryPath
from ghidra.program.model.data import BuiltInDataTypeManager
from ghidra.program.model.data import DataTypeConflictHandler

from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.pcode import HighSymbol

from ghidra.program.model.symbol import SourceType

from ghidra.util.task import ConsoleTaskMonitor

# Caleb's stuff (astlib)
from varlib import datatype, StructDatabase
from varlib.datatype import StructDefinition
from .datatypes import to_varlib_dtype, _struct_to_varlib
from .export_types import update_ghidra_struct_in_sdb

# Normal python stuff
from typing import Dict, List

# Dictionary to map Caleb's (common) builtin data type strings to Ghidra data type paths
ghidra_data_type_by_caleb_data_type = {
    'void'          :   '/void',
    'bool'          :   '/bool',
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
    def __init__(self, program:Program) -> None:

        self.program = program
        # self.sdb = sdb if sdb else StructDatabase()

        # Define data type Category Paths
        self.struct_category_path = CategoryPath('/GhidraRetyper/Structs')
        self.union_category_path = CategoryPath('/GhidraRetyper/Unions')
        self.func_category_path = CategoryPath('/GhidraRetyper/Funcs')

    @property
    def dtype_mgr(self) -> ProgramBasedDataTypeManager:
        '''Returns a handle to the data type manager'''
        return self.program.getDataTypeManager()

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

    def get_retyped_structure_id(self, struct_name:str) -> int:
        matching_structs = [s for s in self.dtype_mgr.allStructures if s.pathName == f'{self.struct_category_path}/{struct_name}']
        if not matching_structs:
            return -1
        # CLS: return None if multiple matches to catch any issues here - we expect unique retyped names
        return matching_structs[0].key if len(matching_structs) == 1 else None

    def update_ghidra_struct_in_sdb(self, sdb:StructDatabase, struct_name:str) -> int:
        '''
        Updates the given struct name in sdb (assumes only one name matches) and
        returns the sid, or None if it was not found
        '''
        return update_ghidra_struct_in_sdb(self.dtype_mgr, struct_name, sdb)

    def define_all_reference_types(self, sdb:StructDatabase, overwrite_existing:bool=False, subset_sids:List[int]=None):
        '''
        Define all of the structure and union types in the reference StructDatabase
        (prior to retyping any variables)

        subset_sids: A subset of structure sids which exist in sdb that should be defined (skipping the rest)
        '''
        # NOTE - don't simply call define_new_structure() iteratively here so we can
        # support definining "complete" data types in an sdb (that may reference other
        # types defined here!)
        structs = sdb.structs_by_id
        unions = sdb.unions_by_id

        struct_subset = {k: v for k, v in structs.items() if k in subset_sids} if subset_sids else structs
        union_subset = {k: v for k, v in unions.items() if k in subset_sids} if subset_sids else unions

        # only check conflicts for types we wish to define
        # NOTE: when we export Ghidra typdefs by resolving to canonical type we will end up with
        #       duplicate names (since tdef -> canonical type whose name is same as canonical type's own entry)
        #       checking conflicts only for struct_items allows us to not worry about this case and simply
        #       handle types we added/updated
        if self.check_conflicts(struct_subset, union_subset):
            raise Exception('ERROR: multiple definitions for the same composite')

        # Iterate through all composites and create empty structs/unions
        for sid, sdef in struct_subset.items():
            # Define empty struct
            new_struct = StructureDataType(self.struct_category_path, sdef.name, 0)
            # CLS NOTE: Dylan had "None" as the 2nd argument instead of "overwrite_existing"
            self.add_to_data_type_manager(new_struct, overwrite_existing)

        for uid, udef in union_subset.items():
            # Define empty union
            new_union = UnionDataType(self.union_category_path, udef.name)
            self.add_to_data_type_manager(new_union, overwrite_existing)

        # Iterate through composites again and add definitions
        for sid, sdef in struct_subset.items():
            # Define internal struct members
            self.define_struct_type(sdef, overwrite_existing)
        for uid, udef in union_subset.items():
            # Define internal union members
            self.define_union_type(udef, overwrite_existing)

    def replace_structure_type(self, orig_sid:int, new_sid:int, update_category_path:bool=False) -> DataType:
        '''
        Replaces occurrences of orig_sid structure type with new_sid structure type (both types
        must already be known to Ghidra) and returns the replacement (Ghidra) DataType.

        NOTE: this should work for other types as well, I'm just using it for structures
        and want to simplify the interface for the common case
        '''
        orig_gdt = self.dtype_mgr.getDataType(orig_sid)
        new_gdt = self.dtype_mgr.getDataType(new_sid)
        return self.dtype_mgr.replaceDataType(orig_gdt, new_gdt, update_category_path)

    def add_to_data_type_manager(self, dtype:DataType, overwrite_existing:bool=False) -> DataType:
        '''
        Add to data type manager and return resulting Ghidra data type
        '''
        # Determine conflict resolution policy
        if overwrite_existing:
            conflict_resolution_policy = DataTypeConflictHandler.REPLACE_HANDLER
        else:
            conflict_resolution_policy = DataTypeConflictHandler.KEEP_HANDLER
        # Add data type to dtm with appropriate conflict resolutin set
        return self.dtype_mgr.addDataType(dtype, conflict_resolution_policy)

    def define_struct_type(self, sdef:datatype.StructDefinition, overwrite_existing:bool=False):
        ghidra_dtype_path = f'{self.struct_category_path}/{sdef.name}'
        new_struct = self.dtype_mgr.getDataType(ghidra_dtype_path)      # retrieve the existing empty struct

        # insert fields into structure IN OFFSET ORDER or it won't work correctly!
        for offset in sorted(sdef.layout.keys()):
            field = sdef.layout[offset]
            dtype = self.convert_dtype(field.dtype)
            # Skip when the field's data type is undefined (should only be enums now)
            if dtype == None:
                print(f"WARNING: {field.dtype} element of structure (category={field.dtype.category}) not found")
                continue
            # Raise exception when the field's data type is undefined
            if dtype.name == 'void':
                raise Exception(f'ERROR: structure {field.dtype} contains void field')
            # Insert field at byte offset defined in layout
            # Length zero means field length determined from data type size
            new_struct.insertAtOffset(offset, dtype, 0, field.name, field.comment)

    def define_union_type(self, udef:datatype.UnionDefinition, overwrite_existing:bool=False):
        # Get empty union from data type manager
        ghidra_dtype_path = f'{self.union_category_path}/{udef.name}'
        new_union = self.dtype_mgr.getDataType(ghidra_dtype_path)
        # Iterate through all fields in union dtype composite and add to empty union
        for field in udef.layout.fields:
            dtype = self.convert_dtype(field.dtype)
            # Skip when the field's data type is undefined (should only be ENUMS now)
            if dtype == None:
                print(f"WARNING: {field.dtype} element of union (category={field.dtype.category}) not found")
                continue
            # Raise exception when the field's data type is undefined
            if dtype.name == 'void':
                raise Exception(f'ERROR: union {field.dtype.name} contains void field')
            # Insert field
            # Length zero means field length determined from data type size
            new_union.add(dtype, 0, field.name, None)

    def update_function_variable(self, symbol:HighSymbol, dtype:datatype.DataType=None, name:str=None):
        '''
        Update the data type and/or name of this symbol (local or parameter)
        '''
        # Update data type
        ghidra_dtype = self.convert_dtype(dtype)
        # Skip when the field's data type is undefined (should only be enums now)
        if not ghidra_dtype:
            raise Exception(f'Error: {symbol.getName()} not updated')

        # This function throws an exception when attempting to update type of unique variable with different size
        HighFunctionDBUtil.updateDBVariable(symbol, name, ghidra_dtype, SourceType.USER_DEFINED)

    def set_globalvar_type(self, global_name:int, global_type:datatype.DataType):
        # do this last: I don't have data for globals right now and we may not need them
        # ...but, while you're doing the others if this is straightforward you can add
        # support for globals too
        raise Exception(f'TODO - implement set_globalvar_type')

    # def set_param_type(self, func_addr:int, param_name:str, dtype:datatype.DataType):
    #     print(f'DYLAN TODO: set decompiler parameter {param_name} in {func_addr:#x} to type {dtype}')

    def set_return_type(self, func_addr:int, dtype:datatype.DataType):
        raise Exception('TODO - implement set_return_type')


    # TODO: move all the type conversion to varlib or wherever I'm already
    # converting from DataType -> Ghidra type

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

    def convert_struct_dtype(self, dtype:datatype.StructType):
        # Generate path and find in program dtm
        ghidra_dtype_path = f'{self.struct_category_path}/{dtype.name}'
        ghidra_dtype = self.dtype_mgr.getDataType(ghidra_dtype_path)

        if not ghidra_dtype:
            # maybe this is an external structure (one we did not recover)
            # --> try to find it by id
            ghidra_dtype = self.dtype_mgr.getDataType(dtype.sid)
            if ghidra_dtype:
                # resolve to canonical type, as we do when we export (we aren't handling typedefs in saphira logic right now)
                ghidra_dtype = ghidra_dtype.baseDataType

        if not ghidra_dtype:
            raise Exception(f'ERROR: STRUCT {dtype.name} not found')

        return ghidra_dtype

    def convert_union_dtype(self, dtype:datatype.DataType):
        # Generate path and find in program dtm
        ghidra_dtype_path = f'{self.union_category_path}/{dtype.name}'
        ghidra_dtype = self.dtype_mgr.getDataType(ghidra_dtype_path)
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
        ghidra_dtype = self.dtype_mgr.getDataType(ghidra_dtype_path)
        if ghidra_dtype == None:
            raise Exception(f'ERROR: FUNC {dtype.name} not found')
        return ghidra_dtype


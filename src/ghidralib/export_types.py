import typing
if typing.TYPE_CHECKING:
    import ghidra
    from ghidra.ghidra_builtins import *
import ghidra
from ghidra.program.model.data import DataTypeManager

from varlib import StructDatabase
from varlib.datatype import StructType, UnionType, StructDefinition, UnionDefinition, StructLayout, UnionLayout, StructField
from wildebeest.utils import show_progress
from .datatypes import to_varlib_dtype

def get_field(dt_comp:ghidra.program.model.data.DataTypeComponent):
    return StructField(to_varlib_dtype(dt_comp.getDataType(), dt_comp.getLength()), dt_comp.getFieldName())

def get_struct_layout(stype:ghidra.program.model.data.Structure) -> StructLayout:
    return StructLayout({x.getOffset(): get_field(x) for x in stype.getComponents()})

def get_struct_definition(stype:ghidra.program.model.data.Structure) -> StructDefinition:
    ghidra_uid = stype.universalID.value    # save this since sids are DIFFERENT
    return StructDefinition(stype.name, get_struct_layout(stype), ghidra_uid=ghidra_uid)

def get_union_layout(utype:ghidra.program.model.data.Union) -> UnionLayout:
    return UnionLayout([get_field(x) for x in utype.getComponents()])

def get_union_definition(utype:ghidra.program.model.data.Union) -> UnionDefinition:
    ghidra_uid = utype.universalID.value    # save this since sids are DIFFERENT
    return UnionDefinition(utype.name, get_union_layout(utype), ghidra_uid=ghidra_uid)

def export_ghidra_types_to_sdb(dtmgr:DataTypeManager) -> StructDatabase:
    # Ghidra already has unique ids - just construct structs/unions_by_id manually
    sdb = StructDatabase()

    for ghidra_type in show_progress(dtmgr.getAllComposites(), total=len(list(dtmgr.getAllComposites()))):
        dtype = to_varlib_dtype(ghidra_type, ghidra_type.getLength())
        if isinstance(dtype, StructType):
            sdb.structs_by_id[dtype.sid] = get_struct_definition(ghidra_type)
        elif isinstance(dtype, UnionType):
            sdb.unions_by_id[dtype.sid] = get_union_definition(ghidra_type)
        else:
            raise Exception(f'Unhandled datatype {type(dtype)}: {dtype}')

    # ok, now map all the Typedef IDs for Typedef'd structs and unions so
    # lookups by Typedef ID will find the canonical type (we don't wrap it
    # with typedef name right now - just return canonical type)
    typedef_types = [x for x in dtmgr.getAllDataTypes() if isinstance(x, ghidra.program.model.data.TypeDef)]

    for td in show_progress(typedef_types, total=len(typedef_types)):
        canonical_type = td.getBaseDataType()
        if isinstance(canonical_type, ghidra.program.model.data.Structure):
            if canonical_type.key not in sdb.structs_by_id:
                raise Exception(f'No mapping for struct {canonical_type} (sid={canonical_type.key})')
            sdb.structs_by_id[td.key] = sdb.structs_by_id[canonical_type.key]
        elif isinstance(canonical_type, ghidra.program.model.data.Union):
            if canonical_type.key not in sdb.unions_by_id:
                raise Exception(f'No mapping for union {canonical_type} (sid={canonical_type.key})')
            sdb.unions_by_id[td.key] = sdb.unions_by_id[canonical_type.key]

    return sdb

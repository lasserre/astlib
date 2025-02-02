import typing
if typing.TYPE_CHECKING:
    import ghidra
    from ghidra.ghidra_builtins import *
import ghidra
from ghidra.program.model.data import DataTypeManager

from tqdm import tqdm

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

def export_ghidra_types_to_sdb(dtmgr:DataTypeManager, progress_bar:bool=True) -> StructDatabase:
    # Ghidra already has unique ids - just construct structs/unions_by_id manually
    sdb = StructDatabase()

    all_composites = list(dtmgr.getAllComposites())
    if progress_bar:
        all_composites = tqdm(all_composites, desc='Exporting structs/unions')

    for ghidra_type in all_composites:
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
    if progress_bar:
        typedef_types = tqdm(typedef_types, desc='Exporting typdefs')

    for td in typedef_types:
        canonical_type = td.getBaseDataType()
        if isinstance(canonical_type, ghidra.program.model.data.Structure):
            if canonical_type.key not in sdb.structs_by_id:
                raise Exception(f'No mapping for struct {canonical_type} (sid={canonical_type.key})')
            sdb.structs_by_id[td.key] = sdb.structs_by_id[canonical_type.key]
        elif isinstance(canonical_type, ghidra.program.model.data.Union):
            if canonical_type.key not in sdb.unions_by_id:
                raise Exception(f'No mapping for union {canonical_type} (sid={canonical_type.key})')
            sdb.unions_by_id[td.key] = sdb.unions_by_id[canonical_type.key]

    sdb.build_sids_by_name()

    return sdb

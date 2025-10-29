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
from .datatypes import to_varlib_dtype, struct_sid

def get_field(sdb:StructDatabase, dt_comp:ghidra.program.model.data.DataTypeComponent):
    return StructField(to_varlib_dtype(sdb, dt_comp.getDataType(), dt_comp.getLength()), dt_comp.getFieldName())

def get_struct_layout(stype:ghidra.program.model.data.Structure, sdb:StructDatabase) -> StructLayout:
    return StructLayout({x.getOffset(): get_field(sdb, x) for x in stype.getDefinedComponents()})

def get_struct_definition(stype:ghidra.program.model.data.Structure, sdb:StructDatabase) -> StructDefinition:
    ghidra_uid = stype.universalID.value    # save this since sids are DIFFERENT
    return StructDefinition(stype.name, get_struct_layout(stype, sdb), ghidra_uid=ghidra_uid)

def get_union_layout(utype:ghidra.program.model.data.Union, sdb:StructDatabase) -> UnionLayout:
    return UnionLayout([get_field(sdb, x) for x in utype.getComponents()])

def get_union_definition(utype:ghidra.program.model.data.Union, sdb:StructDatabase) -> UnionDefinition:
    ghidra_uid = utype.universalID.value    # save this since sids are DIFFERENT
    return UnionDefinition(utype.name, get_union_layout(utype, sdb), ghidra_uid=ghidra_uid)

def get_ghidra_sid(dtmgr:DataTypeManager, struct_name:str) -> int:
    '''
    Returns the ghidra sid for this structure (assuming its name is unique) or None if it DNE
    '''
    matches = [x for x in dtmgr.allComposites if x.name == struct_name]
    return struct_sid(matches[0]) if matches else None

def update_ghidra_struct_in_sdb(dtmgr:DataTypeManager, struct_name:str, sdb:StructDatabase) -> int:
    '''
    Updates the given Ghidra structure in the sdb by mapping its sid in structs_by_id.
    We simply take the first match, so duplicate names won't work here
    '''
    matches = [x for x in dtmgr.allComposites if x.name == struct_name]
    if not matches:
        return None
    gdt = matches[0]
    dtype = to_varlib_dtype(sdb, gdt, gdt.length)
    sdb.map_struct_type('', get_struct_definition(gdt, sdb), is_union=False, force_sid=dtype.sid)
    sdb.build_sids_by_name()
    return dtype.sid

def export_ghidra_types_to_sdb(dtmgr:DataTypeManager, progress_bar:bool=True, tqdm_leave:bool=True) -> StructDatabase:
    # Ghidra already has unique ids - just construct structs/unions_by_id manually
    sdb = StructDatabase()

    all_composites = list(dtmgr.getAllComposites())
    if progress_bar:
        all_composites = tqdm(all_composites, desc='Exporting structs/unions', leave=tqdm_leave)

    for ghidra_type in all_composites:
        dtype = to_varlib_dtype(sdb, ghidra_type, ghidra_type.getLength())
        if isinstance(dtype, StructType):
            sdb.structs_by_id[dtype.sid] = get_struct_definition(ghidra_type, sdb)
        elif isinstance(dtype, UnionType):
            sdb.unions_by_id[dtype.sid] = get_union_definition(ghidra_type, sdb)
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

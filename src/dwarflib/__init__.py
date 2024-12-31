from collections import defaultdict
import posixpath

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.dwarf.dwarfinfo import DWARFInfo, CompileUnit
from elftools.dwarf.die import DIE
from elftools.dwarf.descriptions import ExprDumper, describe_DWARF_expr
from elftools.dwarf.locationlists import *
from elftools.dwarf import constants

from pathlib import Path
import re
from typing import Generator, Iterator, Set, List, Any, Dict

from varlib.datatype import *
from varlib.location import *
from varlib import *

from .systemv import *

GHIDRA_ELF_IMAGE_BASE_DEFAULT_x64 = 0x100000

_is_pie_executable = False

def ghidra_to_dwarf_addr(ghidra_addr:int):
    '''Adjust for Ghidra's default image base'''
    return ghidra_addr - GHIDRA_ELF_IMAGE_BASE_DEFAULT_x64

def dwarf_to_ghidra_addr(dwarf_addr:int):
    '''Adjust for Ghidra's default image base'''
    global _is_pie_executable
    # only add the ghidra image base offset if it's a PIE executable
    return dwarf_addr + GHIDRA_ELF_IMAGE_BASE_DEFAULT_x64 if _is_pie_executable else dwarf_addr

# Foo.b = property(lambda self: self.a + 1)
def die_property(attr_name:str, default_value:Any):
    return property(lambda x: x.attributes[attr_name].value if attr_name in x.attributes else default_value)

def get_namespaces(self:DIE, recursing:bool=False) -> List[str]:
    parent = self.get_parent()
    if parent:
        if parent.tag == 'DW_TAG_namespace':
            if recursing:
                return [*get_namespaces(parent, recursing=True), parent.name]
            return [*get_namespaces(parent, recursing=True), parent.name, self.name]
            # return f'{get_namespaces(parent)}::{self.name}'
    return []

def get_namespace_str(self:DIE) -> str:
    return "::".join(get_namespaces(self))

def get_type_die(self:DIE):
    if 'DW_AT_type' in self.attributes:
        return self.get_DIE_from_attribute('DW_AT_type')
    elif self.abstract_origin:
        return get_type_die(self.abstract_origin)
    return None

def get_die_typename(self:DIE):
    type_die:DIE
    if 'DW_AT_type' not in self.attributes:
        return ''
    type_die = self.get_DIE_from_attribute('DW_AT_type')
    if type_die.tag == 'DW_TAG_base_type':
        if 'DW_AT_type' in type_die.attributes:
            raise Exception(f'Found nested DW_AT_type in base type {type_die.name}??')
        return type_die.name
    elif type_die.tag == 'DW_TAG_class_type':
        return f'class {get_namespace_str(type_die)}'
    elif type_die.tag == 'DW_TAG_structure_type':
        return f'struct {get_namespace_str(type_die)}'
    elif type_die.tag == 'DW_TAG_union_type':
        size = type_die.attributes['DW_AT_byte_size'].value
        return f'union {get_namespace_str(type_die)} (size = 0x{size:x})'
    elif type_die.tag == 'DW_TAG_array_type':
        if not type_die.has_children:
            raise Exception(f'Array type has no children? {type_die}')
        else:
            type_str = f'{get_die_typename(type_die)}'
            for child_die in type_die.iter_children():
                num_elements = child_die.attributes['DW_AT_count'].value
                type_str += f'[{num_elements}]'
            return type_str
    elif type_die.tag == 'DW_TAG_const_type':
        return f'const {get_die_typename(type_die)}'
    elif type_die.tag == 'DW_TAG_typedef':
        # return f'{type_die.name}'     # USE TYPEDEF'D NAME
        return f'{get_die_typename(type_die)}'    # USE BASE/ORIGINAL NAME
        # return f'typedef {get_die_typename(type_die)} {type_die.name}'  # TYPEDEF FORM
    elif type_die.tag == 'DW_TAG_pointer_type':
        if 'DW_AT_type' not in type_die.attributes:
            return f'void*'
        return f'{get_die_typename(type_die)}*'
    elif type_die.tag == 'DW_TAG_enumeration_type':
        return f'enum {get_namespace_str(type_die)}'      # ENUM NAME
        # return f'{get_die_typename(type_die)}'  # UNDERLYING TYPE
    elif type_die.tag == 'DW_TAG_reference_type':
        return f'{type_die.type}&'
    elif type_die.tag == 'DW_TAG_subroutine_type':
        params = [x.type for x in type_die.iter_children() if x.tag == 'DW_TAG_formal_parameter']
        for x in type_die.iter_children():
            if x.tag == 'DW_TAG_unspecified_parameters':
                raise Exception('DW_TAG_unspecified_parameters')
        rtype = type_die.type if 'DW_AT_type' in type_die.attributes else 'void'
        return f'{rtype} {type_die.name}({",".join(params)})'
        import IPython; IPython.embed()
    raise Exception(f'TODO: {type_die.tag}')
    # return f'TODO: {type_die.tag}'

# current struct database (set via UseStructDatabase class)
# holds the current struct database during import from DWARF to varlib
_struct_db:StructDatabase = None

class UseStructDatabase:
    '''
    Convenience 'with' statement wrapper to set/clear the dwarflib _struct_db
    global when we are converting DWARF types to varlib types and storing
    structures within this da
    '''
    def __init__(self, db:StructDatabase):
        self.db = db

    def __enter__(self):
        global _struct_db
        _struct_db = self.db
        return self

    def __exit__(self, exception_type, exception_value, exception_traceback):
        global _struct_db
        _struct_db = None     # reset

def offset_from_memberDIE(mdie:DIE) -> int:
    KEY = 'DW_AT_data_member_location'
    offset = mdie.attributes[KEY].value if KEY in mdie.attributes else 0
    # -1 indicates we encountered a location description, which describes the actual location
    # of this member (for some specific variable) and not its general offset (see DWARF4.pdf pg. 88)
    # right now we don't support this, so return -1 to indicate no offset
    return offset if isinstance(offset, int) else -1

def memberDIE_to_varlib(mdie:DIE):
    return (offset_from_memberDIE(mdie), StructField(dtype=die_to_dtype(mdie.type_die), name=mdie.name))

def get_layout_from_structDIE(sdie:DIE) -> StructLayout:
    '''
    Converts the DW_TAG_structure_type DIE to a StructLayout by processing its DW_TAG_member children
    '''
    member_dies = [memberDIE_to_varlib(mdie) for mdie in sdie.iter_children() if mdie.tag == 'DW_TAG_member']
    return StructLayout({x[0]: x[1] for x in member_dies})

def get_layout_from_unionDIE(udie:DIE) -> UnionLayout:
    return UnionLayout([memberDIE_to_varlib(mdie)[1] for mdie in udie.iter_children() if mdie.tag == 'DW_TAG_member'])

def get_fllayout_for_struct(sdie:DIE) -> Dict[int, str]:
    return {offset_from_memberDIE(mdie): die_to_dtype(mdie.type_die, typename_basic=True).typename_basic  \
                     for mdie in sdie.iter_children() if mdie.tag == 'DW_TAG_member'}

def get_fllayout_for_union(udie:DIE) -> Set[str]:
    return set(die_to_dtype(mdie.type_die, typename_basic=True).typename_basic for mdie in udie.iter_children() if mdie.tag == 'DW_TAG_member')

def structDIE_to_varlib(sdie:DIE, name:str, is_class:bool=False):
    return get_record_type_from_die(sdie, name, is_union=False, is_class=is_class)

def get_record_type_from_die(die:DIE, name:str, is_union:bool, is_class:bool=False):
    global _struct_db

    is_fwd_decl = 'DW_AT_declaration' in die.attributes
    # tuid = ''   # try without differentiating by TU
    tuid = die.cu.get_top_DIE().name

    sid = _struct_db.get_sid(tuid, name, is_union) if name else -1    # we can't look up anonymous unions/structs by name

    if name == '':
        # these will all collide in name for now, but otherwise anonymous types cause errors
        name = f'anonymous_{"union" if is_union else "struct"}'

    if sid == -1:
        # unmapped type - need to define it
        if is_union:
            sid = _struct_db.map_union_type_empty(tuid, name)   # map new union with this name
            utype = UnionType(_struct_db, sid)
            utype.layout = get_layout_from_unionDIE(die)
            return utype
        else:
            # 1. map a new structure with this name (creates sid)
            sid = _struct_db.map_struct_type_empty(tuid, name, is_class)
            stype = StructType(_struct_db, sid)
            # 2. NOW define fields (after mapping to prevent recursion issues)
            stype.layout = get_layout_from_structDIE(die)
            return stype
    elif is_union:
        utype = UnionType(_struct_db, sid)
        if utype.empty and not is_fwd_decl:
            # existing type has no fields but this DIE has the definition
            # (this is same as below, but struct version has more comments)
            utype.layout = UnionLayout([StructField(BuiltinType.create_void_type(), 'DUMMY')])
            utype.layout = get_layout_from_unionDIE(die)
        return utype
    else:
        stype = StructType(_struct_db, sid)     # get existing type from sid
        if stype.empty and not is_fwd_decl:
            # existing type has no fields (is a fwd decl), but this DIE
            # actually has the real definition --> update the layout in the database

            # NOTE: this is a microcasm of the bigger problem - if I don't
            # "map" the fact that layout is being set FIRST, I will still recurse
            # here forever if this layout is recursive!
            # -> set a dummy member here to indicate we have a layout (actually set below)
            stype.layout = StructLayout({0: StructField(BuiltinType.create_void_type(), 'DUMMY')})

            # now that stype.empty will return FALSE if we have a recursively defined type,
            # we can go ahead and (re)set the actual layout now
            stype.layout = get_layout_from_structDIE(die)
        return stype

def unionDIE_to_varlib(udie:DIE, name:str):
    return get_record_type_from_die(udie, name, is_union=True)

_basetype_encoding_to_tuple = {
    # value: (isFloating, isSigned)
    2: (False, False),  # DW_ATE_boolean
    3: (True, True),    # DW_ATE_complex_float
    4: (True, True),    # DW_ATE_float
    5: (False, True),   # DW_ATE_signed
    6: (False, True),   # DW_ATE_signed_char
    7: (False, False),  # DW_ATE_unsigned
    8: (False, False),  # DW_ATE_unsigned_char
    16: (False, True),  # DW_ATE_UTF - treat these like "bigger" char's (short, int32, ... bigger signed integers)
}

def getDwarfBaseTypeEncodingAttrs(DW_ATE_encoding:int):
    '''
    Returns the (isFloating, isSigned) tuple for this base type encoding value

    e.g. input of 8 corresponds to DW_ATE_unsigned_char and returns (False, False)
    '''
    if DW_ATE_encoding not in _basetype_encoding_to_tuple:
        # import IPython; IPython.embed()
        raise Exception(f'Unrecognized DWARF base type encoding value: {DW_ATE_encoding}')

    return _basetype_encoding_to_tuple[DW_ATE_encoding]

def get_typename(self:DIE, typedef_name:str=''):
    if not self.name and typedef_name:
        return typedef_name    # use the typedef name if child doesn't have one
    return self.name

_qualifier_tags = [
    'DW_TAG_const_type',
    'DW_TAG_volatile_type',
    'DW_TAG_restrict_type',
]

def _get_array_nelems_from_subrange(srdie:DIE):
    if srdie.upper_bound and not isinstance(srdie.upper_bound, list):
        return srdie.upper_bound + 1
    elif srdie.count:
        return srdie.count
    else:
        return None   # unknown size

# to_varlib_dtype(self) becomes die_to_dtype(self.type_die) if type_die else None

def die_to_dtype(self:DIE, typedef_name:str='', typename_basic:bool=False) -> DataType:
    if self.tag == 'DW_TAG_typedef' or self.tag in _qualifier_tags:
        # resolve to canonical type
        return die_to_dtype(self.type_die, self.name, typename_basic) if self.type_die is not None else BuiltinType.create_void_type()
    elif self.tag == 'DW_TAG_structure_type' or self.tag == 'DW_TAG_class_type':
        name = get_typename(self, typedef_name)
        # support gathering C++ class structure layouts
        is_class=self.tag == 'DW_TAG_class_type'
        stype = StructTypeBasic(name) if typename_basic else structDIE_to_varlib(self, name, is_class)
        return stype
    elif self.tag == 'DW_TAG_pointer_type':
        ptype = PointerType(None, self.byte_size)
        ptype.pointed_to = die_to_dtype(self.type_die, typedef_name, typename_basic) if self.type_die is not None else BuiltinType.create_void_type()
        return ptype
    elif self.tag == 'DW_TAG_base_type':
        is_float, is_signed = getDwarfBaseTypeEncodingAttrs(self.encoding)
        return BuiltinType(self.name, is_float, is_signed, self.byte_size)
    elif self.tag == 'DW_TAG_array_type':
        # subrange = [x for x in self.iter_children() if x.tag == 'DW_TAG_subrange_type'][0]
        subranges = [x for x in self.iter_children() if x.tag == 'DW_TAG_subrange_type']
        arrtype = ArrayType(None, num_elements=1)

        # for multi-dim array - array dim sizes are in L-R order
        current = arrtype
        for i, arr_dim in enumerate([_get_array_nelems_from_subrange(sr) for sr in subranges]):
            current.num_elements = arr_dim
            if i < len(subranges)-1:
                current.element_type = ArrayType(None, num_elements=1)
                current = current.element_type      # point to next layer down

        # overwrite final layer with actual contained type
        current.element_type = die_to_dtype(self.type_die, typedef_name, typename_basic)

        # return top-level type
        return arrtype
    elif self.tag == 'DW_TAG_union_type':
        name = get_typename(self, typedef_name)
        return UnionTypeBasic(self.name) if typename_basic else unionDIE_to_varlib(self, name)
    elif self.tag == 'DW_TAG_subroutine_type':
        fproto = FunctionType(None, [], typedef_name)
        if not typename_basic:
            # only grab the signature if we're doing the full definition
            fproto.return_dtype = die_to_dtype(self.type_die) if self.type_die else BuiltinType.create_void_type()
            fproto.params = [die_to_dtype(p.type_die) for p in self.iter_children() if p.tag == 'DW_TAG_formal_parameter']
        return fproto
    elif self.tag == 'DW_TAG_enumeration_type':
        name = get_typename(self)
        return EnumType(name)

    # C++ workarounds...
    if self.tag == 'DW_TAG_reference_type' or \
       self.tag == 'DW_TAG_rvalue_reference_type':
        # HACK: treat reference types as pointers for now
        ptype = PointerType(None, self.byte_size)
        ptype.pointed_to = die_to_dtype(self.type_die, typedef_name, typename_basic) if self.type_die is not None else BuiltinType.create_void_type()
        return ptype
    elif self.tag == 'DW_TAG_ptr_to_member_type':
        # HACK: treat ptr_to_member (C++-ism) as void*
        return PointerType(BuiltinType.create_void_type(), self.byte_size)
    elif self.tag == 'DW_TAG_unspecified_type':
        if self.name == 'decltype(nullptr)':
            return PointerType(BuiltinType.create_void_type(), self.byte_size)
        print(f'Returning None for DW_TAG_unspecified_type {self.name}')
        return None

    raise Exception(f'UNHANDLED type_die tag: {self.tag}')
    # print(f'UNHANDLED type_die tag: {self.tag}')
    # import IPython; IPython.embed()

def to_varlib_location(self:DIE):
    loc_str = self.location_str
    if not loc_str:
        return Location(LocationType.Undefined)
    elif ';' in loc_str:
        # print(f'Skipping DWARF location {loc_str}...')
        return Location(LocationType.Undefined)

    if loc_str.startswith('DW_OP_fbreg'):
        # deref_str = '; DW_OP_deref'
        # if loc_str.endswith(deref_str):
        #     # just remove this for now...
        #     loc_str = loc_str[:-len(deref_str)]
        cfa_offset = int(loc_str.split(':')[1].strip())
        # NOTE: this assumes 64-bit code where CFA is the stack pointer at the call site
        # just before the return IP is pushed
        ghidra_stack_offset = cfa_offset + 8
        return Location(LocationType.Stack, offset=ghidra_stack_offset)
    elif loc_str.startswith('DW_OP_addr'):
        dwarf_addr = int(loc_str.split(':')[1].strip(), 16)     # this looks to be in hex always?
        ghidra_addr = dwarf_to_ghidra_addr(dwarf_addr)
        return Location(LocationType.Memory, offset=ghidra_addr)
    elif loc_str.startswith('DW_OP_reg'):
        parts = loc_str.split(' (')
        if len(parts) < 2:
            raise Exception(f'Unexpected DWARF register string "{loc_str}"')
        regname = parts[1][:-1]     # take everything but closing paren
        return Location(LocationType.Register, reg_name=regname)
    elif loc_str.startswith('DW_OP_bregx'):
        # NOTE: have to check bregx FIRST since we also have breg[0..31]
        pass    # TODO - handle bregx when I have a test case...
    elif loc_str.startswith('DW_OP_breg'):
        # breg[0..31]
        m = re.match('.*\((.+)\):\s+(\S+)', self.location_str)
        regname = m.groups()[0]
        offset = int(m.groups()[1])
        return Location(LocationType.Memory, reg_name=regname, offset=offset)

    raise Exception(f'Handle DWARF location: {self.location_str}')
    # import IPython; IPython.embed()

def get_die_location(self:DIE):
    d = ExprDumper(self.dwarfinfo.structs)
    loc_parser = LocationParser(self.dwarfinfo.location_lists())

    if 'DW_AT_location' in self.attributes:
        loc = loc_parser.parse_from_attribute(self.attributes['DW_AT_location'], self.cu['version'], self)
        if isinstance(loc, LocationExpr):
            # simple expression
            return d.dump_expr(loc.loc_expr)
        elif isinstance(loc, list):
            # location list
            return ''
            # raise Exception(f'Found location list for DIE named {self.name}')
            # return [(x, d.dump_expr(x.loc_expr)) for x in loc]
        else:
            raise Exception(f'Unrecognized location: {loc}')
    return ''

def find_struct_tag(self:DIE) -> DIE:
    if self.tag == 'DW_TAG_structure_type' or self.tag == 'DW_TAG_class_type':
        return self
    elif self.tag == 'DW_TAG_base_type' or self.tag == 'DW_TAG_union_type':
        return None
    elif 'DW_AT_type' not in self.attributes:
        return None

    type_die:DIE
    type_die = self.get_DIE_from_attribute('DW_AT_type')
    return find_struct_tag(type_die)

def resolve_abstract_origin(self:DIE) -> DIE:
    if 'DW_AT_abstract_origin' in self.attributes:
        abs_orig = self.attributes['DW_AT_abstract_origin']
        if abs_orig.form == 'DW_FORM_ref_addr':
            return self.dwarfinfo.get_DIE_from_refaddr(abs_orig.value)
        else:
            # CLS: only handling DW_FORM_ref_addr so far
            print(f"Warning: unable to resolve abstract origin of the form: {abs_orig.form}")
    return None

def get_die_name(self:DIE) -> str:
    if 'DW_AT_name' in self.attributes:
        return self.attributes['DW_AT_name'].value.decode()
    elif self.abstract_origin:
        return get_die_name(self.abstract_origin)
    return ''

# DIE.name = die_property('DW_AT_name', b'')
DIE.name = property(get_die_name)
DIE.namebytes = die_property('DW_AT_name', b'')
# external => visible outside its compilation unit
DIE.external = die_property('DW_AT_external', False)
# DIE.location = die_property('DW_AT_location', None)
DIE.location_str = property(lambda x: get_die_location(x))
DIE.location_varlib = property(to_varlib_location)
DIE.low_pc = die_property('DW_AT_low_pc', None)
DIE.high_pc = die_property('DW_AT_high_pc', None)
DIE.type_die = property(get_type_die)
DIE.type_name = property(get_die_typename)

# DIE.dtype_varlib = property(to_varlib_dtype)

# NEW dtype_varlib needs to be:
# typedie_dtype -> convert .type_die to DataType
DIE.typedie_dtype = property(lambda x: die_to_dtype(x.type_die) if x.type_die else None)
# dtype -> convert (self) to DataType
DIE.dtype = property(die_to_dtype)

DIE.byte_size = die_property('DW_AT_byte_size', None)
DIE.encoding = die_property('DW_AT_encoding', None)
DIE.artificial = die_property('DW_AT_artificial', None)
DIE.upper_bound = die_property('DW_AT_upper_bound', None)
DIE.count = die_property('DW_AT_count', None)
DIE.inline = die_property('DW_AT_inline', None)
DIE.language = die_property('DW_AT_language', None)
DIE.abstract_origin = property(resolve_abstract_origin)

# CLS: taken from dwarf_lineprogram_filenames.py example in pyelftools
def line_entry_mapping(line_program):
    filename_map = defaultdict(int)

    # The line program, when decoded, returns a list of line program
    # entries. Each entry contains a state, which we'll use to build
    # a reverse mapping of filename -> #entries.
    lp_entries = line_program.get_entries()
    for lpe in lp_entries:
        # We skip LPEs that don't have an associated file.
        # This can happen if instructions in the compiled binary
        # don't correspond directly to any original source file.
        if not lpe.state or lpe.state.file == 0:
            continue
        filename = lpe_filename(line_program, lpe.state.file)
        filename_map[filename] += 1

    for filename, lpe_count in filename_map.items():
        print("    filename=%s -> %d entries" % (filename, lpe_count))

# CLS: taken from dwarf_lineprogram_filenames.py example in pyelftools
def lpe_filename(line_program, file_index):
    # Retrieving the filename associated with a line program entry
    # involves two levels of indirection: we take the file index from
    # the LPE to grab the file_entry from the line program header,
    # then take the directory index from the file_entry to grab the
    # directory name from the line program header. Finally, we
    # join the (base) filename from the file_entry to the directory
    # name to get the absolute filename.
    lp_header = line_program.header
    file_entries = lp_header["file_entry"]

    # File and directory indices are 1-indexed.
    file_entry = file_entries[file_index - 1]
    dir_index = file_entry["dir_index"]

    # A dir_index of 0 indicates that no absolute directory was recorded during
    # compilation; return just the basename.
    if dir_index == 0:
        return file_entry.name.decode()

    directory = lp_header["include_directory"][dir_index - 1]
    return posixpath.join(directory, file_entry.name).decode()

_LANG_TO_NAME = {
    constants.DW_LANG_C89: 'C89',
    constants.DW_LANG_C: 'C',
    constants.DW_LANG_Ada83: 'Ada83',
    constants.DW_LANG_C_plus_plus: 'C_plus_plus',
    constants.DW_LANG_Cobol74: 'Cobol74',
    constants.DW_LANG_Cobol85: 'Cobol85',
    constants.DW_LANG_Fortran77: 'Fortran77',
    constants.DW_LANG_Fortran90: 'Fortran90',
    constants.DW_LANG_Pascal83: 'Pascal83',
    constants.DW_LANG_Modula2: 'Modula2',
    constants.DW_LANG_Java: 'Java',
    constants.DW_LANG_C99: 'C99',
    constants.DW_LANG_Ada95: 'Ada95',
    constants.DW_LANG_Fortran95: 'Fortran95',
    constants.DW_LANG_PLI: 'PLI',
    constants.DW_LANG_ObjC: 'ObjC',
    constants.DW_LANG_ObjC_plus_plus: 'ObjC_plus_plus',
    constants.DW_LANG_UPC: 'UPC',
    constants.DW_LANG_D: 'D',
    constants.DW_LANG_Python: 'Python',
    constants.DW_LANG_OpenCL: 'OpenCL',
    constants.DW_LANG_Go: 'Go',
    constants.DW_LANG_Modula3: 'Modula3',
    constants.DW_LANG_Haskell: 'Haskell',
    constants.DW_LANG_C_plus_plus_03: 'C_plus_plus_03',
    constants.DW_LANG_C_plus_plus_11: 'C_plus_plus_11',
    constants.DW_LANG_OCaml: 'OCaml',
    constants.DW_LANG_Rust: 'Rust',
    constants.DW_LANG_C11: 'C11',
    constants.DW_LANG_Swift: 'Swift',
    constants.DW_LANG_Julia: 'Julia',
    constants.DW_LANG_Dylan: 'Dylan',
    constants.DW_LANG_C_plus_plus_14: 'C_plus_plus_14',
    constants.DW_LANG_Fortran03: 'Fortran03',
    constants.DW_LANG_Fortran08: 'Fortran08',
    constants.DW_LANG_RenderScript: 'RenderScript',
    constants.DW_LANG_BLISS: 'BLISS',
    constants.DW_LANG_Mips_Assembler: 'Mips_Assembler',
    constants.DW_LANG_Upc: 'Upc',
    constants.DW_LANG_HP_Bliss: 'HP_Bliss',
    constants.DW_LANG_HP_Basic91: 'HP_Basic91',
    constants.DW_LANG_HP_Pascal91: 'HP_Pascal91',
    constants.DW_LANG_HP_IMacro: 'HP_IMacro',
    constants.DW_LANG_HP_Assembler: 'HP_Assembler',
    constants.DW_LANG_GOOGLE_RenderScript: 'GOOGLE_RenderScript',
    constants.DW_LANG_BORLAND_Delphi: 'BORLAND_Delphi',
}

class DwarfDebugInfo:
    def __init__(self, dwarf:DWARFInfo, is_pie:bool, c_cpp_only:bool=True) -> None:
        self.dwarf = dwarf
        self.is_pie = is_pie    # true if this is a position-independent exe or a shared object
        self.funcdies_by_addr:Dict[int,DIE] = {}
        # multilevel dict maps (file:str, line:int, col:int) triples -> address:int
        self.lineinfo_lookup:Dict[tuple, int] = {}
        # self.lineinfo_lookup:Dict[Dict[str,Dict[int,Dict[int,int]]]] = {}

        self._build_funcdies_by_addr(c_cpp_only)
        # don't call _build_lineinfo_lookup() in case we don't need it

    @staticmethod
    def is_exe_or_sharedobj(elf_file:Path) -> bool:
        with open(elf_file, 'rb') as f:
            ef = ELFFile(f)
            return ef.structs.e_type == 'ET_DYN' or ef.structs.e_type == 'ET_EXEC'

    @staticmethod
    def is_PIE_or_sharedobj(elf:ELFFile) -> bool:
        return elf.structs.e_type == 'ET_DYN'

    @staticmethod
    def fromElf(elf_file:Path, c_cpp_only:bool=True) -> 'DwarfDebugInfo':
        '''
        Create a new DwarfDebugInfo instance from the path to an ELF executable
        '''
        with open(elf_file, 'rb') as f:
            ef = ELFFile(f)
            dwarf = ef.get_dwarf_info()
            is_pie = DwarfDebugInfo.is_PIE_or_sharedobj(ef)
            init_pyelftools_from_dwarf(dwarf, is_pie)
        return DwarfDebugInfo(dwarf, is_pie, c_cpp_only)

    def _build_funcdies_by_addr(self, c_cpp_only:bool=True):
        for fdie in self.get_function_dies(c_cpp_only=c_cpp_only):
            if fdie.low_pc is not None:
                self.funcdies_by_addr[fdie.low_pc] = fdie
            # else:
            #     print(f'Skipping function {fdie.name} since it has no low_pc address')

    def _build_lineinfo_lookup(self):
        if self.lineinfo_lookup:
            print(f'lineinfo_lookup already constructed! Reset it first if you want to truly rebuild')
            return

        for CU in self.dwarf.iter_CUs():
            line_program = self.dwarf.line_program_for_CU(CU)
            for lpe in line_program.get_entries():
                # COPIED COMMENT FROM pyelftools dwarf_lineprogram_filenames.py:
                # --------------
                # We skip LPEs that don't have an associated file.
                # This can happen if instructions in the compiled binary
                # don't correspond directly to any original source file.
                if not lpe.state or lpe.state.file == 0:
                    continue
                line_num = lpe.state.line
                col_num = lpe.state.column  # aha! this should help match
                filename = lpe_filename(line_program, lpe.state.file)
                dwarf_address = lpe.state.address
                self.lineinfo_lookup[(filename, line_num, col_num)] = dwarf_address

                # this gives us:
                # (FILE, LINE, COL) -> ADDRESS
                # might be interesting to see if we have cases where differing
                # columns (same line and file) give us different addresses...IF SO,
                # THIS WOULD BE AWESOME - more sure we're looking at the correct
                # AST node...

    def get_function_dies(self, cu_list:List[CompileUnit]=None, c_cpp_only:bool=True) -> List[DIE]:
        '''
        If cu_list is None then all cu's will be included
        '''
        global _LANG_TO_NAME

        if not cu_list:
            cu_list = list(self.dwarf.iter_CUs())

        # CLS: filter on this list to only allow C/C++
        lang_list = [
            constants.DW_LANG_C,
            constants.DW_LANG_C89,
            constants.DW_LANG_C99,
            constants.DW_LANG_C11,
            constants.DW_LANG_C_plus_plus,
            constants.DW_LANG_C_plus_plus_03,
            constants.DW_LANG_C_plus_plus_11,
            constants.DW_LANG_C_plus_plus_14,
        ]

        filtered_cu_list = [cu for cu in cu_list if cu.get_top_DIE().language in lang_list] if c_cpp_only else cu_list

        if len(filtered_cu_list) < len(cu_list):
            skipped_langs = [cu.get_top_DIE().language for cu in cu_list if cu not in filtered_cu_list]
            for lang in sorted(set(skipped_langs)):
                print(f'Skipping CU\'s written in {_LANG_TO_NAME[lang]}')

        return [die for cu in filtered_cu_list for die in cu.get_top_DIE().iter_children() if die.tag == 'DW_TAG_subprogram']

    def get_function_params(self, func:DIE):
        # TODO: implement a function to convert AST to graph (see Jupyter nb)
        # TODO: extend graph function to highlight MEMBER offset nodes with
        # an outline color...
        for x in func.iter_children():
            x:DIE
            if x.tag == 'DW_TAG_formal_parameter':
                yield x

    def get_function_locals(self, func:DIE):
        return list(self.extract_variables_from_die_tree(func))

    def get_typedef_dies(self) -> List[DIE]:
        return [d for cu in self.dwarf.iter_CUs() for d in cu.iter_DIEs() if d.tag == 'DW_TAG_typedef']

    def extract_variables_from_die_tree(self, die:DIE) -> Generator[DIE,None,None]:
        '''
        Recursively extracts all DW_TAG_variable instances nested below
        this DIE in the tree
        '''
        for x in die.iter_children():
            x:DIE
            if x.tag == 'DW_TAG_variable':
                yield x
            elif x.has_children:
                yield from self.extract_variables_from_die_tree(x)

    def find_function(self, function_name:str) -> DIE:
        matches = [f for f in self.get_function_dies() if f.namebytes.decode() == function_name]
        return matches[0] if matches else None

def init_pyelftools_from_dwarf(dwarf:DWARFInfo, is_pie:bool):
    '''
    Call this first to work aroudn a pyelftools bug

    CLS: this is a bug in pyelftools - the _MACHINE_ARCH is unset
    when we dump an expression (really this shouldn't be global at all)
    -> quick fix: just set this manually to match current DWARF info
    before dumping anything
    '''
    global _is_pie_executable

    # CLS: piggybacking on the fact we already have to init pyelftools' global
    # state - set our "is_pie" state globally at the same time here
    # obviously a hack, but this will work with minimal code changes for now
    _is_pie_executable = is_pie

    from elftools.dwarf.descriptions import _MACHINE_ARCH
    from elftools.dwarf.descriptions import set_global_machine_arch
    set_global_machine_arch(dwarf.config.machine_arch)

def old_main(ris):
    with open(ris, 'rb') as f:
        ef = ELFFile(f)
        dwarf = ef.get_dwarf_info()



        ddi = DwarfDebugInfo(dwarf)
        # ddi.get_functions()

        # TODO: start getting CU's (compilation units) and iterating through
        # their debug information entries (DIEs) to find the data we need
        # (refer to the DWARF standard,
        #  see https://developer.ibm.com/articles/au-dwarf-debug-format/)

        cu = list(dwarf.iter_CUs())[0]
        die = cu.get_top_DIE()

        ft = ddi.find_function('FileText')
        ft_vars = ddi.get_function_locals(ft)
        v0 = ft_vars[0]

        d = ExprDumper(dwarf.structs)
        # d.dump_expr(v0.location)
        # print(v0.location)
        # loc = d.expr_parser.parse_expr(v0.location)

        # for i, v in enumerate(ft_vars):
        #     print(f'Local var {i+1}: {v.namebytes.decode()}, location={v.location}')

        # fc = ddi.find_function('FutureCheck')
        # fcvars = ddi.get_function_locals(fc)

        # print(f'Variables for function {fc.name}:')
        # for x in fcvars:
        #     print(f'  {x.type} {x.name}\t@ {x.location}')

        named_funcs = sorted(set([f.name for f in ddi.get_function_dies() if f.name]))

        # take the first function:
        fdie = ddi.find_function(named_funcs[0])
        f_locals = ddi.get_function_locals(fdie)
        locations = [x.location for x in f_locals]
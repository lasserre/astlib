import json
from pathlib import Path
from typing import Dict, List, Any, Tuple, Callable

from .astvisitor import *
from .astviewer import ASTViewer, NodeAttrs

from varlib import datatype, location, StructDatabase, StructType, StructLayout, StructTypeBasic
from varlib.datatype import UnionType, UnionTypeBasic

_ast_class_by_name = {}

_space_mapping = {
    'register': location.LocationType.Register,
    'stack': location.LocationType.Stack,
    'join': location.LocationType.Join,
    'unique': location.LocationType.Unique,
}

# current struct database (set via UseStructDatabase class)
# holds the current struct database during import from DWARF to varlib
_struct_db:StructDatabase = None

class UseStructDatabase:
    '''
    Convenience 'with' statement wrapper to set/clear the astlib _struct_db
    global when we are converting AST types to varlib types and storing
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

def to_varlib_location(node:ASTNode) -> location.Location:
    if not hasattr(node, 'loc_space'):
        return None

    if not node.loc_space:
        return None

    if node.loc_space not in _space_mapping:
        raise Exception(f'Unhandled AST loc_space "{node.loc_space}"')

    loc_type = _space_mapping[node.loc_space]
    loc_off = node.loc_off if loc_type != location.LocationType.Register else 0
    return location.Location(loc_type, node.loc_reg, loc_off)

def get_fllayout_for_struct(node:ASTNode):
    return {off: to_varlib_dtype(f.dtype, typename_basic=True).typename_basic
                        for off, f in node.fields_by_offset.items()}

def structtype_to_varlib(node:ASTNode):
    if node.is_union:
        utype = datatype.UnionType([], node.name)
        utype.fields = [datatype.StructField(to_varlib_dtype(f.dtype), f.name) for f in node.fields]
        return utype

    # default struct case
    global _struct_db
    tuid = node.tuid
    is_fwd_decl = False     # assuming no fwd decls in our AST structs?
    sid = _struct_db.get_sid(tuid, node.name, is_fwd_decl, lambda: get_fllayout_for_struct(node))

    if sid == -1:
        # unmapped type - need to define it
        sid = _struct_db.map_struct_type_empty(tuid, node.name)    # 1. map a new structure with this name (creates sid)
        stype = StructType(_struct_db, sid)                         # 2. NOW define fields (after mapping to prevent recursion issues)
        stype.layout = StructLayout({off: datatype.StructField(to_varlib_dtype(f.dtype), f.name)
                                for off, f in node.fields_by_offset.items()})
        return stype
    else:
        stype = StructType(_struct_db, sid)     # get existing type from sid
        return stype

def to_varlib_dtype(node:ASTNode, typename_basic:bool=False) -> datatype.DataType:
    '''
    Converts the AST Type node to its corresponding varlib data type, or
    returns None if the node is not a data type node.
    '''
    if node.kind == 'BuiltinType':
        return datatype.BuiltinType(node.name, node.is_floating_point, node.is_signed, node.size)
    elif node.kind == 'PointerType':
        ptype = datatype.PointerType(None, node.size)
        ptype.pointed_to = to_varlib_dtype(node.inner[0], typename_basic)
        return ptype
    elif node.kind == 'StructType':
        if typename_basic:
            return UnionTypeBasic(node.name) if node.is_union else StructTypeBasic(node.name)
        return structtype_to_varlib(node)
    elif node.kind == 'ConstantArrayType':
        atype = datatype.ArrayType(None, num_elements=node.num_elements)
        atype.element_type = to_varlib_dtype(node.inner[0], typename_basic)
        return atype
    elif node.kind == 'VoidType':
        return datatype.BuiltinType('void', False, False, 0)
    elif node.kind == 'EnumType':
        return datatype.EnumType(node.name)
    elif node.kind == 'FunctionType':
        # NOTE: node.name is not what I want ideally (rather have the typedef name)...but at least it's consistent
        fptype = datatype.FunctionType(None, [], node.name)
        if not typename_basic:
            fptype.return_dtype = to_varlib_dtype(node.return_dtype)
            fptype.params = [to_varlib_dtype(p) for p in node.inner]
        return fptype
    elif node.kind == 'TypedefType':
        # convert to canonical type (remove typdefs)
        return to_varlib_dtype(node.decl.inner[0], typename_basic)
    elif node.kind == 'Type':
        # SOMETHING WENT WRONG during Ghidra AST export
        # we do create these, but only 1) if there was an unhandled metatype and
        # 2) as a placeholder for undefinedX types (which are getting replaced
        #    with builtin types)
        # -> unhandled metatypes should be filtered out as failed funcs via .log
        #    files, so this probably means our placeholder did not get processed
        # **I've seen this happen for types Ghidra mishandles - like a function
        #   argument that was: "int (*) []" (pointer to dimensionless array of int)
        #   and Ghidra reported this as TYPE_UNKNOWN with size of 1!
        #
        # workaround: treat this as Void and move on...I think this is very rare
        # and likely stems from a problem we can't solve - Ghidra mishandling types
        return datatype.BuiltinType.create_void_type()
    elif node.kind.endswith('Type'):
        # print(f'Unhandled AST type node "{node.kind}"')
        # import IPython; IPython.embed()
        raise Exception(f'Unhandled AST type node "{node.kind}"')

    return None     # not a data type AST node

_statement_node_kinds = [
    'BreakStmt',
    'CaseStmt',
    # 'CompoundStmt'    # not really...this is just a container of statements
    'DeclStmt',
    'DoStmt',
    'ForStmt',
    'GotoStmt',
    'IfStmt',
    'LabelStmt',
    'ReturnStmt',
    'SwitchStmt',
    'WhileStmt'
]

def _new_astnode_class_from_dict(d:Dict, tuid:str):#=''):
    '''
    Creates a new class derived from ASTNode with a classname matching
    the 'kind' field in the dictionary (e.g. VarDecl, FunctionDecl, etc.)
    '''
    if d['kind'] in _ast_class_by_name:
        return _ast_class_by_name[d['kind']]

    def _handle_attached_types(self:'NewClass'):
        if self.kind == 'ConstantArrayType':
            self.__class__.size = property(lambda self: self.inner[0].size * self.num_elements)
        if self.kind == 'CStyleCastExpr':
            self.dtype = _new_astnode_class_from_dict(self.dtype, tuid)(self.dtype, tuid)
            self.dtype.parent = self
            self.dtype.is_parent_attached = True
        elif self.kind == 'FieldDecl':
            self.dtype = _new_astnode_class_from_dict(self.dtype, tuid)(self.dtype, tuid)
            self.dtype.parent = self
            self.dtype.is_parent_attached = True
        elif self.kind == 'FunctionDecl':
            self.return_dtype = _new_astnode_class_from_dict(self.return_dtype, tuid)(self.return_dtype, tuid)
            self.return_dtype.parent = self
            self.return_dtype.is_parent_attached = True
        elif self.kind == 'FunctionType':
            self.return_dtype = _new_astnode_class_from_dict(self.return_dtype, tuid)(self.return_dtype, tuid)
            self.return_dtype.parent = self
            self.return_dtype.is_parent_attached = True
        elif self.kind == 'VarDecl' or self.kind == 'ParmVarDecl':
            self.dtype = _new_astnode_class_from_dict(self.dtype, tuid)(self.dtype, tuid)
            self.dtype.parent = self
            self.dtype.is_parent_attached = True
        elif self.kind == 'RecordDecl':
            # same thing as StructType, except all we lack here is the name
            # (we don't really use RecordDecl other than validation)
            if not hasattr(self.__class__, 'name'):
                self.__class__.name = property(lambda self: self._struct_def.name)
        elif self.kind == 'StructType':
            # pass everything through to self._struct_def
            # default value, we expect this to be overwritten
            self._struct_def = StructDef('NO_STRUCTDEF', -1, [])
            if not hasattr(self.__class__, 'name'):
                self.__class__.name = property(lambda self: self._struct_def.name)
                self.__class__.size = property(lambda self: self._struct_def.size)
                self.__class__.fields = property(lambda self: self._struct_def.fields)
                self.__class__.fields_by_offset = property(
                    lambda self: self._struct_def.fields_by_offset if not self.is_union else None)
        elif self.kind == 'TypedefType':
            self.__class__.size = property(lambda self: self.decl.inner[0].size)

    class NewClass(ASTNode):
        def __init__(self, data:Dict, tuid:str):#=''):
            self.__dict__.update(data)
            if 'inner' in self.__dict__:
                # self.__dict__['inner'] = [_new_astnode_class_from_dict(child)(child) for child in self.__dict__['inner']]
                self.inner = [_new_astnode_class_from_dict(x, tuid)(x, tuid) for x in self.inner]
                for child in self.inner:
                    child.parent = self
                    child.is_parent_attached = False
            else:
                self.inner = []

            self.tuid = tuid

            _handle_attached_types(self)

        def render(self, format='pdf', outfolder=None, ast_name:str='',
                    fontname:str='Cascadia Code',
                    format_node:Callable[[ASTNode,NodeAttrs],Any]=None):
            '''
            outfolder: If set, the AST graph rendering will be saved in the desired format
                       within this folder. If outfolder is None, no files will be written
            '''
            return ASTViewer(format_node).render_ast(self, format, outfolder, ast_name, fontname)

        def dtype_str(self):
            return DatatypePrinter().to_string(self)

        def has_types(self, node_types:List[str], has_any:bool=True):
            return HasNodeTypesVisitor(node_types, has_any).visit(self)

        def nodes_at_addr(self, addr:int) -> List[ASTNode]:
            return GetNodesAtAddr(addr).visit(self)

        @property
        def is_statement(self) -> bool:
            # examples:
            # x = y;
            # my_func();
            # for (i = 0; i < DECLREF; i++)
            return (self.kind == 'BinaryOperator' and self.opcode == '=') \
                or (self.kind == 'CallExpr' and self.parent and self.parent.kind == 'CompoundStmt') \
                or self.kind in _statement_node_kinds

        @property
        def dtype_varlib(self) -> datatype.DataType:
            '''Returns the varlib data type if this node is Type node, otherwise None'''
            return to_varlib_dtype(self)

        @property
        def location(self) -> location.Location:
            return to_varlib_location(self)

    NewClass.__name__ = d['kind']
    NewClass.__qualname__ = d['kind']
    _ast_class_by_name[d['kind']] = NewClass
    return NewClass

class FieldDef:
    '''
    Represents information about a structure field
    '''
    def __init__(self, name:str, offset:int, dtype:ASTNode) -> None:
        self.name = name
        self.offset = offset
        self.dtype = dtype

class StructDef:
    '''
    Since StructType is a thin wrapper around the sid, we need a separate type
    to represent the definition of the struct in the structures_by_id dictionary
    '''
    def __init__(self, name:str, sid:int, fields_by_offset:Dict[int, FieldDef]) -> None:
        self.name = name
        self.sid = sid
        self.fields_by_offset = fields_by_offset

    @property
    def is_union(self):
        return False

    @property
    def fields(self) -> List[FieldDef]:
        return [self.fields_by_offset[k] for k in sorted(self.fields_by_offset.keys())]

    @property
    def size(self) -> int:
        return sum([f.dtype.size for f in self.fields_by_offset.values()])

class UnionDef:
    '''
    Same as StructDef, but for unions (because we can't map fields by offset)
    '''
    def __init__(self, name:str, sid:int, fields:List[FieldDef]) -> None:
        self.name = name
        self.sid = sid
        self.fields = fields

    @property
    def is_union(self):
        return True

def create_struct_def(sdict:dict, sid:int, tuid:str=''):
    fields_by_offset = {}
    if sdict['fields']:
        for offset, fdict in sdict['fields'].items():
            dtype_dict = fdict['dtype']
            dtype = _new_astnode_class_from_dict(dtype_dict, tuid)(dtype_dict, tuid)
            fields_by_offset[int(offset)] = FieldDef(fdict['name'], offset, dtype)
    return StructDef(sdict['name'], int(sid), fields_by_offset)

def create_union_def(sdict:dict, sid:int, tuid:str=''):
    fields = []
    if sdict['fields']:
        for fdict in sdict['fields']:
            dtype_dict = fdict['dtype']
            dtype = _new_astnode_class_from_dict(dtype_dict, tuid)(dtype_dict, tuid)
            fields.append(FieldDef(fdict['name'], 0, dtype))
    return UnionDef(sdict['name'], sid, fields)

def convert_structures_by_id(structs_by_id:Dict, tuid:str='') -> Dict[int, StructDef]:
    structs = {}
    for sid, sdict in structs_by_id.items():
        structs[int(sid)] = create_union_def(sdict, sid, tuid) if sdict['is_union'] else \
                            create_struct_def(sdict, sid, tuid)
    return structs

def dict_to_ast(d:dict, tuid:str='') -> Tuple[ASTNode, Dict[int, StructDef]]:
    '''
    Convert the dictionary read in from JSON back to an AST object, returning the
    top-level TranslationUnit node and struct_lib dictionary

    d: Dictionary read from JSON to be converted
    tuid: An identifying string for this translation unit (used by varlib to differentiate
          and map structs from different translation units sharing the same name which
          may or may not share the same definition)
    '''
    if d['kind'] != 'TranslationUnitDecl':
        raise Exception(f'Expected dict to be a translation unit, found "{d["kind"]}" instead')

    ast = _new_astnode_class_from_dict(d, tuid)(d, tuid)
    struct_lib = convert_structures_by_id(d['structures_by_id'], tuid)
    StructTypeAndValueDeclLookup(struct_lib).extract(ast, save_result=True)

    return (ast, struct_lib)

def json_to_ast(json_file:Path):
    with open(json_file) as f:
        data = json.load(f)
    return dict_to_ast(data, json_file.stem)

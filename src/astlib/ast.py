import json
from pathlib import Path
from typing import Dict, List, Any, Tuple, Callable

from .astvisitor import *
from .astviewer import ASTViewer, NodeAttrs

from varlib import datatype, location

_ast_class_by_name = {}

_space_mapping = {
    'register': location.LocationType.Register,
    'stack': location.LocationType.Stack,
}

def to_varlib_location(node:ASTNode) -> location.Location:
    if not hasattr(node, 'loc_space'):
        return None

    if node.loc_space not in _space_mapping:
        raise Exception(f'Unhandled AST loc_space "{node.loc_space}"')

    loc_type = _space_mapping[node.loc_space]
    return location.Location(loc_type, node.loc_reg, node.loc_off)

def to_varlib_dtype(node:ASTNode, parent:datatype.DataType=None) -> datatype.DataType:
    '''
    Converts the AST Type node to its corresponding varlib data type, or
    returns None if the node is not a data type node.
    '''
    if node.kind == 'BuiltinType':
        return datatype.BuiltinType(node.name, node.is_floating_point, node.is_signed, node.size)
    elif node.kind == 'PointerType':
        ptype = datatype.PointerType(None, node.size, parent)
        ptype.pointed_to = to_varlib_dtype(node.inner[0], parent=ptype)
        return ptype
    elif node.kind == 'StructType':
        if node.is_union:
            return datatype.UnionType(node.fields, node.name, parent)
        else:
            pnode = parent
            while pnode is not None:
                if pnode.category == datatype.DataTypeCategories.Struct and pnode.name == node.name:
                    return datatype.RecursiveStructType(pnode, parent)
                pnode = pnode.parent
            stype = datatype.StructType({}, node.name, parent)
            dt_fields = {off: datatype.StructField(to_varlib_dtype(f.dtype, stype), f.name) for off, f in node.fields_by_offset.items()}
            stype.fields_by_offset = dt_fields
            return stype
    elif node.kind == 'ConstantArrayType':
        atype = datatype.ArrayType(None, num_elements=node.num_elements, parent=parent)
        atype.element_type = to_varlib_dtype(node.inner[0], parent=atype)
        return atype
    elif node.kind == 'VoidType':
        return datatype.BuiltinType('void', False, False, 0)
    elif node.kind.endswith('Type'):
        raise Exception(f'Unhandled AST type node "{node.kind}"')

    return None     # not a data type AST node

def _new_astnode_class_from_dict(d:Dict):
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
            self.dtype = _new_astnode_class_from_dict(self.dtype)(self.dtype)
            self.dtype.parent = self
            self.dtype.is_parent_attached = True
        elif self.kind == 'FieldDecl':
            self.dtype = _new_astnode_class_from_dict(self.dtype)(self.dtype)
            self.dtype.parent = self
            self.dtype.is_parent_attached = True
        elif self.kind == 'FunctionDecl':
            self.return_dtype = _new_astnode_class_from_dict(self.return_dtype)(self.return_dtype)
            self.return_dtype.parent = self
            self.return_dtype.is_parent_attached = True
        elif self.kind == 'FunctionType':
            self.return_dtype = _new_astnode_class_from_dict(self.return_dtype)(self.return_dtype)
            self.return_dtype.parent = self
            self.return_dtype.is_parent_attached = True
        elif self.kind == 'VarDecl' or self.kind == 'ParmVarDecl':
            self.dtype = _new_astnode_class_from_dict(self.dtype)(self.dtype)
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
        def __init__(self, data:Dict):
            self.__dict__.update(data)
            if 'inner' in self.__dict__:
                # self.__dict__['inner'] = [_new_astnode_class_from_dict(child)(child) for child in self.__dict__['inner']]
                self.inner = [_new_astnode_class_from_dict(x)(x) for x in self.inner]
                for child in self.inner:
                    child.parent = self
                    child.is_parent_attached = False
            else:
                self.inner = []

            _handle_attached_types(self)

        def render(self, format='pdf', outfolder=Path.cwd(), ast_name:str='',
                    fontname:str='Cascadia Code',
                    format_node:Callable[[ASTNode,NodeAttrs],Any]=None):
            return ASTViewer(format_node).render_ast(self, format, outfolder, ast_name, fontname)

        def dtype_str(self):
            return DatatypePrinter().to_string(self)

        def has_types(self, node_types:List[str], has_any:bool=True):
            return HasNodeTypesVisitor(node_types, has_any).visit(self)

        def nodes_at_addr(self, addr:int) -> List[ASTNode]:
            return GetNodesAtAddr(addr).visit(self)

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

def create_struct_def(sdict:dict, sid:int):
    fields_by_offset = {}
    if sdict['fields']:
        for offset, fdict in sdict['fields'].items():
            dtype_dict = fdict['dtype']
            dtype = _new_astnode_class_from_dict(dtype_dict)(dtype_dict)
            fields_by_offset[int(offset)] = FieldDef(fdict['name'], offset, dtype)
    return StructDef(sdict['name'], int(sid), fields_by_offset)

def create_union_def(sdict:dict, sid:int):
    fields = []
    if sdict['fields']:
        for fdict in sdict['fields']:
            dtype_dict = fdict['dtype']
            dtype = _new_astnode_class_from_dict(dtype_dict)(dtype_dict)
            fields.append(FieldDef(fdict['name'], 0, dtype))
    return UnionDef(sdict['name'], sid, fields)

def convert_structures_by_id(structs_by_id:Dict) -> Dict[int, StructDef]:
    structs = {}
    for sid, sdict in structs_by_id.items():
        structs[int(sid)] = create_union_def(sdict, sid) if sdict['is_union'] else \
                            create_struct_def(sdict, sid)
    return structs

def dict_to_ast(d:dict) -> Tuple[ASTNode, Dict[int, StructDef]]:
    if d['kind'] != 'TranslationUnitDecl':
        raise Exception(f'Expected dict to be a translation unit, found "{d["kind"]}" instead')
    ast = _new_astnode_class_from_dict(d)(d)
    struct_lib = convert_structures_by_id(d['structures_by_id'])
    StructTypeAndValueDeclLookup(struct_lib).extract(ast, save_result=True)
    return (ast, struct_lib)

def json_to_ast(json_file:Path):
    with open(json_file) as f:
        data = json.load(f)
    return dict_to_ast(data)

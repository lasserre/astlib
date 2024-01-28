import json
import sys, inspect
from pathlib import Path
from typing import Callable, Any, List, Dict

from varlib import StructDatabase
from varlib.datatype import DataType, datatype_from_dict
from varlib.location import Location, LocationType

from .astvisitor import DatatypePrinter, HasNodeTypesVisitor, GetNodesAtAddr
from .astviewer import ASTViewer, NodeAttrs

_space_mapping = {
    'register': LocationType.Register,
    'stack': LocationType.Stack,
    'join': LocationType.Join,
    'unique': LocationType.Unique,
}

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

class ASTNode:
    '''
    Base class for all concrete AST nodes
    '''
    def __init__(self, parent:'ASTNode'=None):
        self.inner = []
        self.parent = parent
        self.is_parent_attached:bool = False
        self.location:Location = None
        self.dtype:DataType = None

    def add_child(self, child:'ASTNode'):
        self.inner.append(child)
        child.parent = self

    # this visitor_method_name lookup is the accept() part of the implementation.
    # instead of each node type manually calling the appropriate visit_mynode()
    # function, we can dynamically locate the intended function and call it
    # here based on the node's type
    @property
    def visitor_method_name(self) -> str:
        return f'visit_{self.kind}'

    def render(self, format='pdf', outfolder=None, ast_name:str='',
                fontname:str='Cascadia Code',
                format_node:Callable[['ASTNode',NodeAttrs],Any]=None):
        '''
        outfolder: If set, the AST graph rendering will be saved in the desired format
                    within this folder. If outfolder is None, no files will be written
        '''
        return ASTViewer(format_node).render_ast(self, format, outfolder, ast_name, fontname)

    def dtype_str(self):
        return DatatypePrinter().to_string(self)

    def has_types(self, node_types:List[str], has_any:bool=True):
        return HasNodeTypesVisitor(node_types, has_any).visit(self)

    def nodes_at_addr(self, addr:int) -> List['ASTNode']:
        return GetNodesAtAddr(addr).visit(self)

    @property
    def is_statement(self) -> bool:
        global _statement_node_kinds
        # examples:
        # x = y;
        # my_func();
        # for (i = 0; i < DECLREF; i++)
        return (self.kind == 'BinaryOperator' and self.opcode == '=') \
            or (self.kind == 'CallExpr' and self.parent and self.parent.kind == 'CompoundStmt') \
            or self.kind in _statement_node_kinds

    def _children_from_dict(self, d:dict, sdb:StructDatabase):
        '''Helper function for ASTNodes to read in their child nodes'''
        for child_dict in d['inner']:
            self.add_child(astnode_from_dict(child_dict, sdb))

    def to_dict(self) -> dict:
        '''Converts the data type into a serializable dict'''
        return {
            'kind': str(self.__class__.__name__),
            'inner': [n.to_dict() for n in self.inner]
        }

#######################################################################
# AST Node Types

class CompoundStmt(ASTNode):
    def __init__(self):
        super().__init__()

    @staticmethod
    def from_dict(d:dict, sdb:StructDatabase) -> 'CompoundStmt':
        cs = CompoundStmt()
        cs._children_from_dict(d, sdb)
        return cs

class ValueDecl(ASTNode):
    def __init__(self, id:int):
        super().__init__()
        self.id = id

    def to_dict(self) -> dict:
        return {
            **self.to_dict(),
            'id': self.id
        }

    @staticmethod
    def from_dict(d:dict, sdb:StructDatabase) -> 'ValueDecl':
        return ValueDecl(d['id'])

class VarDecl(ValueDecl):
    def __init__(self, id:int, name:str, dtype:DataType, loc:Location):
        super().__init__(id)
        self.name = name
        self.dtype = dtype
        self.location = loc

    def to_dict(self) -> dict:
        return {
            **super().to_dict(),
            'name': self.name,
            'dtype': self.dtype.to_dict(),
            **self.location.to_dict(),  # 'paste' the location dict inside ours (instead of nesting)
        }

    @staticmethod
    def from_dict(d:dict, sdb:StructDatabase) -> 'VarDecl':
        return VarDecl(d['id'], d['name'],
                        datatype_from_dict(d['dtype'], sdb),
                        Location.from_dict(d))

class ParmVarDecl(VarDecl):
    def __init__(self, id:int, name:str, dtype:DataType, loc:Location):
        super().__init__(id, name, dtype, loc)

    # don't override to_dict(): same as VarDecl

    @staticmethod
    def from_dict(d:dict, sdb:StructDatabase) -> 'ParmVarDecl':
        vd = VarDecl.from_dict(d, sdb)  # same as VarDecl dict
        return ParmVarDecl(vd.parent, vd.id, vd.name, vd.dtype, vd.location)

class FunctionDecl(ValueDecl):
    def __init__(self, id:int, name:str, address:int, is_intrinsic:bool, return_dtype:DataType, params:List[ParmVarDecl]):
        super().__init__(id)
        self.name = name
        self.address = address
        self.is_intrinsic = is_intrinsic
        self.return_dtype = return_dtype
        for p in params:
            self.add_child(p)

    def to_dict(self) -> dict:
        return {
            **super().to_dict(),
            'name': self.name,
            'address': f'{self.address:x}',
            'is_instrinsic': self.is_intrinsic,
            'return_dtype': self.return_dtype.to_dict(),
        }

    @staticmethod
    def from_dict(d:dict, sdb:StructDatabase) -> 'FunctionDecl':
        fd = FunctionDecl(d['id'], d['name'], int(d['address'], 16),
            d['is_intrinsic'],
            datatype_from_dict(d['return_dtype'], sdb),
            params=[])
        fd._children_from_dict(d, sdb)  # read params from inner
        return fd

class TranslationUnitDecl(ASTNode):
    def __init__(self):
        super().__init__()

    @staticmethod
    def from_dict(d:dict, sdb:StructDatabase) -> 'TranslationUnitDecl':
        tudecl = TranslationUnitDecl()
        tudecl._children_from_dict(d, sdb)
        return tudecl

#######################################################################
# All AST nodes must be defined above _get_module_classes() so all the
# class types get picked up automatically

def _get_module_classes() -> Dict[str, type]:
    '''Return a mapping from name to type for all classes in the current module'''
    global _current_module
    return {name: classtype for name, classtype in inspect.getmembers(_current_module) if inspect.isclass(classtype)}

_current_module = sys.modules[__name__]
_module_classes:dict = _get_module_classes()

def astnode_from_dict(d:dict, sdb:StructDatabase=None) -> ASTNode:
    global _module_classes
    if d['kind'] not in _module_classes:
        raise NotImplementedError(f'No ASTNode class defined for node type "{d["kind"]}"')
    return _module_classes[d['kind']].from_dict(d, sdb)

def read_json(json_file:Path) -> ASTNode:
    with open(json_file) as f:
        data = json.load(f)
    # TODO: later, look for a .sdb file in the same folder, read it in and pass the
    # struct database along
    return astnode_from_dict(data)


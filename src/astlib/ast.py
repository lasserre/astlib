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
    def __init__(self, parent:'ASTNode'):
        self.inner = []
        self.parent = parent
        self.is_parent_attached:bool = False
        self.location:Location = None
        self.dtype:DataType = None

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

    def _get_base_dict(self) -> dict:
        return {
            'kind': str(self.__class__.__name__)
        }

    def _children_from_dict(self, d:dict, sdb:StructDatabase):
        '''Helper function for ASTNodes to read in their child nodes'''
        self.inner = [astnode_from_dict(child_dict, self, sdb) for child_dict in d['inner']]

    def to_dict(self) -> dict:
        '''Converts the data type into a serializable dict'''
        raise NotImplementedError(f'to_dict not implemented in {self.__class__.__name__}')

#######################################################################
# AST Node Types

class TranslationUnitDecl(ASTNode):
    def __init__(self, parent: ASTNode):
        super().__init__(parent)

    @staticmethod
    def from_dict(d:dict, parent:ASTNode, sdb:StructDatabase) -> 'TranslationUnitDecl':
        tudecl = TranslationUnitDecl(parent)
        tudecl._children_from_dict(d, sdb)
        return tudecl

class VarDecl(ASTNode):
    def __init__(self, parent: ASTNode, id:int, name:str, dtype:DataType, loc:Location):
        super().__init__(parent)
        self.id = id
        self.name = name
        self.dtype = dtype
        self.location = loc

    @staticmethod
    def from_dict(d:dict, parent:ASTNode, sdb:StructDatabase) -> 'VarDecl':
        return VarDecl(parent, int(d['id']),
                        d['name'],
                        datatype_from_dict(d['dtype'], sdb),
                        Location.from_dict(d))

#######################################################################
# All AST nodes must be defined above _get_module_classes() so all the
# class types get picked up automatically

def _get_module_classes() -> Dict[str, type]:
    '''Return a mapping from name to type for all classes in the current module'''
    global _current_module
    return {name: classtype for name, classtype in inspect.getmembers(_current_module) if inspect.isclass(classtype)}

_current_module = sys.modules[__name__]
_module_classes:dict = _get_module_classes()

def astnode_from_dict(d:dict, parent:ASTNode=None, sdb:StructDatabase=None) -> ASTNode:
    global _module_classes
    if d['kind'] not in _module_classes:
        raise NotImplementedError(f'No ASTNode class defined for node type "{d["kind"]}"')
    return _module_classes[d['kind']].from_dict(d, parent, sdb)

def read_json(json_file:Path) -> ASTNode:
    with open(json_file) as f:
        data = json.load(f)
    # TODO: later, look for a .sdb file in the same folder, read it in and pass the
    # struct database along
    return astnode_from_dict(data)


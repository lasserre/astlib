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

class FromDictContext:
    '''Container to carry around context needed for ASTNodes' from_dict methods'''
    def __init__(self, sdb:StructDatabase, tudecl:'TranslationUnitDecl'=None) -> None:
        self.sdb = sdb
        self.tudecl = tudecl

class ASTNode:
    '''
    Base class for all concrete AST nodes
    '''
    def __init__(self, instr_addr:int=0, parent:'ASTNode'=None):
        self.inner = []
        self.parent = parent
        self.is_parent_attached:bool = False
        self.location:Location = None
        self.dtype:DataType = None
        self.instr_addr = instr_addr

    def add_child(self, child:'ASTNode'):
        self.inner.append(child)
        child.parent = self

    @property
    def kind(self) -> str:
        return self.__class__.__name__

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

    def _children_from_dict(self, d:dict, ctx:FromDictContext):
        '''Helper function for ASTNodes to read in their child nodes'''
        if 'inner' in d:
            for child_dict in d['inner']:
                self.add_child(astnode_from_dict(child_dict, ctx))

    def to_dict(self) -> dict:
        '''Converts the data type into a serializable dict'''
        return {
            'kind': self.kind,
            'inner': [n.to_dict() for n in self.inner],
            'instr_addr': self.instr_addr,
        }

#######################################################################
# AST Node Types

class ArraySubscriptExpr(ASTNode):
    def __init__(self, instr_addr:int=0):
        super().__init__(instr_addr)

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'ArraySubscriptExpr':
        expr = ArraySubscriptExpr(d['instr_addr'])
        expr._children_from_dict(d, ctx)
        return expr

class BinaryOperator(ASTNode):
    def __init__(self, opcode:str, instr_addr:int=0):
        super().__init__(instr_addr)
        self.opcode = opcode

    def to_dict(self) -> dict:
        return {
            **super().to_dict(),
            'opcode': self.opcode,
        }

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'BinaryOperator':
        op = BinaryOperator(d['opcode'], d['instr_addr'])
        op._children_from_dict(d, ctx)
        return op

class BreakStmt(ASTNode):
    def __init__(self):
        super().__init__()

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'BreakStmt':
        bs = BreakStmt()
        bs._children_from_dict(d, ctx)
        return bs

class CompoundStmt(ASTNode):
    def __init__(self):
        super().__init__()

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'CompoundStmt':
        cs = CompoundStmt()
        cs._children_from_dict(d, ctx)
        return cs

class CStyleCastExpr(ASTNode):
    def __init__(self, dtype:DataType, instr_addr:int = 0):
        super().__init__(instr_addr)
        self.dtype = dtype

    def to_dict(self) -> dict:
        return {
            **super().to_dict(),
            'dtype': self.dtype.to_dict(),
        }

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'CStyleCastExpr':
        cc = CStyleCastExpr(datatype_from_dict(d['dtype'], ctx.sdb), d['instr_addr'])
        cc._children_from_dict(d, ctx)
        return cc

_decl_types = {
    1: 'FunctionDecl',
    2: 'VarDecl',
    3: 'EnumDecl'
}

class EnumConstantDecl(ASTNode):
    '''
    Not a full-fledged EnumConstantDecl - just a thin wrapper that
    DeclRefExpr can return for referenced enum types (since we don't
    want to export the full definition)
    '''
    def __init__(self, name:str, value:int):
        super().__init__()

class DeclRefExpr(ASTNode):
    def __init__(self, tudecl:'TranslationUnitDecl', referenced_id:int=-1, decl_type:int=-1, instr_addr:int=-1):
        super().__init__(instr_addr=instr_addr)
        self.referenced_id = referenced_id
        self.decl_type = decl_type
        self.enum_name = ''
        self.enum_val = -1
        self._tudecl = tudecl

    @property
    def decl_type_str(self) -> str:
        global _decl_types
        if self.decl_type in _decl_types:
            return _decl_types[self.decl_type]
        return f'Unrecognized DeclType {self.decl_type}'

    @property
    def tudecl(self) -> 'TranslationUnitDecl':
        return self._tudecl

    @property
    def referencedDecl(self) -> 'ValueDecl':
        if self.decl_type == 3:
            return EnumConstantDecl(self.enum_name, self.enum_val)
        return self.tudecl._decls_by_id[self.referenced_id]

    def to_dict(self) -> dict:
        d = {
            **super().to_dict(),
            'type': self.decl_type,
            'referencedDecl_id': self.referenced_id,
        }
        if self.enum_name:
            d['enum_const_name'] = self.enum_name
            d['enum_const_value'] = self.enum_val
        return d

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'DeclRefExpr':
        dre = DeclRefExpr(ctx.tudecl, d['referencedDecl_id'], d['type'], d['instr_addr'])
        if 'enum_const_name' in d:
            dre.enum_name = d['enum_const_name']
        if 'enum_const_value' in d:
            dre.enum_val = d['enum_const_value']
        dre._children_from_dict(d, ctx)
        return dre

class DeclStmt(ASTNode):
    def __init__(self):
        super().__init__()

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'DeclStmt':
        ds = DeclStmt()
        ds._children_from_dict(d, ctx)
        return ds

class CallExpr(ASTNode):
    def __init__(self, declRefExpr:ASTNode=None, args:List[ASTNode]=None):
        super().__init__()
        if declRefExpr:
            self.add_child(declRefExpr)
        if args:
            for a in args:
                self.add_child(a)

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'CallExpr':
        cexpr = CallExpr()
        cexpr._children_from_dict(d, ctx)
        return cexpr

class CharacterLiteral(ASTNode):
    def __init__(self, value:str, dtype:DataType, instr_addr:int=0):
        super().__init__(instr_addr)
        self.value = value
        self.dtype = dtype

    def to_dict(self) -> dict:
        return {
            **super().to_dict(),
            'value': self.value,
            'dtype': self.dtype.to_dict(),
        }

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'CharacterLiteral':
        return CharacterLiteral(d['value'], datatype_from_dict(d['dtype'], ctx.sdb), d['instr_addr'])

class CaseStmt(ASTNode):
    def __init__(self):
        super().__init__()

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'CaseStmt':
        cs = CaseStmt()
        cs._children_from_dict(d, ctx)
        return cs

class ConstantExpr(ASTNode):
    def __init__(self):
        super().__init__()

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'ConstantExpr':
        cs = ConstantExpr()
        cs._children_from_dict(d, ctx)
        return cs

class DefaultStmt(ASTNode):
    def __init__(self):
        super().__init__()

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'DefaultStmt':
        ds = DefaultStmt()
        ds._children_from_dict(d, ctx)
        return ds

class DoStmt(ASTNode):
    def __init__(self, instr_addr:int=0):
        super().__init__(instr_addr)

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'DoStmt':
        ds = DoStmt(d['instr_addr'])
        ds._children_from_dict(d, ctx)
        return ds

class FloatingLiteral(ASTNode):
    def __init__(self, value:float, special_value:str, dtype:DataType, instr_addr:int=0):
        super().__init__(instr_addr)
        self.value = value
        self.special_value = special_value
        self.dtype = dtype

    def to_dict(self) -> dict:
        return {
            **super().to_dict(),
            'value': self.value,
            'special_value': self.special_value,
            'dtype': self.dtype.to_dict(),
        }

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'FloatingLiteral':
        fl = FloatingLiteral(d['value'], d['special_value'],
            datatype_from_dict(d['dtype'], ctx.sdb), d['instr_addr'])
        fl._children_from_dict(d, ctx)
        return fl

class ForStmt(ASTNode):
    def __init__(self, instr_addr:int=0):
        super().__init__(instr_addr)

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'ForStmt':
        fs = ForStmt(d['instr_addr'])
        fs._children_from_dict(d, ctx)
        return fs

class GotoStmt(ASTNode):
    def __init__(self, label_name:str, instr_addr:int=0):
        super().__init__(instr_addr)
        self.label_name = label_name

    def to_dict(self) -> dict:
        return {
            **super().to_dict(),
            'label_name': self.label_name,
        }

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'GotoStmt':
        gs = GotoStmt(d['label_name'], d['instr_addr'])
        gs._children_from_dict(d, ctx)
        return gs

class IfStmt(ASTNode):
    def __init__(self, instr_addr:int=0):
        super().__init__(instr_addr)

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'IfStmt':
        ifs = IfStmt(d['instr_addr'])
        ifs._children_from_dict(d, ctx)
        return ifs

class IntegerLiteral(ASTNode):
    def __init__(self, value:int, dtype:DataType, instr_addr:int=0):
        super().__init__(instr_addr)
        self.value = value
        self.dtype = dtype

    def to_dict(self) -> dict:
        return {
            **super().to_dict(),
            'value': self.value,
            'dtype': self.dtype.to_dict(),
        }

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'IntegerLiteral':
        return IntegerLiteral(d['value'], datatype_from_dict(d['dtype'], ctx.sdb), d['instr_addr'])

class LabelStmt(ASTNode):
    def __init__(self, name:str, instr_addr:int=0):
        super().__init__(instr_addr)
        self.name = name

    def to_dict(self) -> dict:
        return {
            **super().to_dict(),
            'name': self.name,
        }

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'LabelStmt':
        ls = LabelStmt(d['name'], d['instr_addr'])
        ls._children_from_dict(d, ctx)
        return ls

class MemberExpr(ASTNode):
    def __init__(self, sid:int, offset:int, name:str, is_arrow:bool, instr_addr:int=0, sdb:StructDatabase=None):
        super().__init__(instr_addr)
        self.sid = sid
        self.offset = offset
        self.name = name
        self.is_arrow = is_arrow
        self.sdb = sdb

    @property
    def parent_struct(self):
        if self.sdb:
            if self.sid in self.sdb.structs_by_id:
                return self.sdb.structs_by_id[self.sid]
            return self.sdb.unions_by_id[self.sid]
        return None

    def to_dict(self) -> dict:
        return {
            **super().to_dict(),
            'name': self.name,
            'sid': self.sid,
            'offset': self.offset,
            'isArrow': self.is_arrow,
        }

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'MemberExpr':
        me = MemberExpr(d['sid'], d['offset'], d['name'], d['isArrow'], d['instr_addr'], ctx.sdb)
        me._children_from_dict(d, ctx)
        return me

class NullNode(ASTNode):
    def __init__(self):
        super().__init__()

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'NullNode':
        nn = NullNode()
        nn._children_from_dict(d, ctx)
        return nn

class ParenExpr(ASTNode):
    def __init__(self, instr_addr:int=0):
        super().__init__(instr_addr)

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'ParenExpr':
        pe = ParenExpr(d['instr_addr'])
        pe._children_from_dict(d, ctx)
        return pe

class ReturnStmt(ASTNode):
    def __init__(self, instr_addr:int = 0):
        super().__init__(instr_addr)

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'ReturnStmt':
        rs = ReturnStmt(d['instr_addr'])
        rs._children_from_dict(d, ctx)
        return rs

class StringLiteral(ASTNode):
    def __init__(self, value:str, instr_addr:int=0):
        super().__init__(instr_addr)
        self.value = value

    def to_dict(self) -> dict:
        return {
            **super().to_dict(),
            'value': self.value,
        }

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'StringLiteral':
        return StringLiteral(d['value'], d['instr_addr'])

class SwitchStmt(ASTNode):
    def __init__(self, instr_addr:int=0):
        super().__init__(instr_addr)

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'SwitchStmt':
        ss = SwitchStmt(d['instr_addr'])
        ss._children_from_dict(d, ctx)
        return ss

class ValueDecl(ASTNode):
    def __init__(self, id:int):
        super().__init__()
        self.id = id

    def to_dict(self) -> dict:
        return {
            **super().to_dict(),
            'id': self.id
        }

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'ValueDecl':
        vd = ValueDecl(d['id'])
        ctx.tudecl._decls_by_id[vd.id] = vd
        vd._children_from_dict(d, ctx)
        return vd

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
    def from_dict(d:dict, ctx:FromDictContext) -> 'VarDecl':
        vd = VarDecl(d['id'], d['name'],
                        datatype_from_dict(d['dtype'], ctx.sdb),
                        Location.from_dict(d))
        ctx.tudecl._decls_by_id[vd.id] = vd
        vd._children_from_dict(d, ctx)
        return vd

class ParmVarDecl(VarDecl):
    def __init__(self, id:int, name:str, dtype:DataType, loc:Location):
        super().__init__(id, name, dtype, loc)

    # don't override to_dict(): same as VarDecl

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'ParmVarDecl':
        vd = VarDecl.from_dict(d, ctx)  # same as VarDecl dict
        pvdecl = ParmVarDecl(vd.id, vd.name, vd.dtype, vd.location)
        ctx.tudecl._decls_by_id[pvdecl.id] = pvdecl     # point to ParmVarDecl, not VarDecl
        pvdecl._children_from_dict(d, ctx)
        return pvdecl

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
            'address': self.address,
            'is_instrinsic': self.is_intrinsic,
            'return_dtype': self.return_dtype.to_dict(),
        }

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'FunctionDecl':
        fd = FunctionDecl(d['id'], d['name'], d['address'],
            d['is_intrinsic'],
            datatype_from_dict(d['return_dtype'], ctx.sdb),
            params=[])
        ctx.tudecl._decls_by_id[fd.id] = fd
        fd._children_from_dict(d, ctx)  # read params from inner
        return fd

class UnaryOperator(ASTNode):
    def __init__(self, opcode:str, instr_addr:int=0):
        super().__init__(instr_addr)
        self.opcode = opcode

    def to_dict(self) -> dict:
        return {
            **super().to_dict(),
            'opcode': self.opcode,
        }

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'UnaryOperator':
        op = UnaryOperator(d['opcode'], d['instr_addr'])
        op._children_from_dict(d, ctx)
        return op

class WhileStmt(ASTNode):
    def __init__(self, instr_addr:int=0):
        super().__init__(instr_addr)

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'WhileStmt':
        ws = WhileStmt(d['instr_addr'])
        ws._children_from_dict(d, ctx)
        return ws

class TranslationUnitDecl(ASTNode):
    def __init__(self):
        super().__init__()

        # build up this mapping as we read from dict
        # so references can reach back to the decl
        self._decls_by_id:Dict[int,ValueDecl] = {}

    @staticmethod
    def from_dict(d:dict, ctx:FromDictContext) -> 'TranslationUnitDecl':
        tudecl = TranslationUnitDecl()
        ctx.tudecl = tudecl     # there is only one translation unit, so we're it!
        tudecl._children_from_dict(d, ctx)
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

def astnode_from_dict(d:dict, ctx:FromDictContext=None) -> ASTNode:
    global _module_classes
    if d['kind'] not in _module_classes:
        raise NotImplementedError(f'No ASTNode class defined for node type "{d["kind"]}"')
    return _module_classes[d['kind']].from_dict(d, ctx)

def read_json(json_file:Path) -> ASTNode:
    with open(json_file) as f:
        data = json.load(f)
    # TODO: later, look for a .sdb file in the same folder, read it in and pass the
    # struct database along
    ctx = FromDictContext(sdb=None)
    return astnode_from_dict(data, ctx)


from enum import Enum
from typing import List

from varlib.datatype import DataType, DataTypeCategories
from varlib.location import Location, LocationType

# CLS: wasn't sure the best place for this but I need to be able to reuse it
# in various places so it makes sense to come along with dwarflib right now

class ArgClass(Enum):
    SSE = 1

_builtins_to_argclass = {
    'double': ArgClass.SSE
}

def type_to_argclass(dt:DataType) -> ArgClass:
    if dt.category == DataTypeCategories.BuiltIn:
        if dt.standard_name not in _builtins_to_argclass:
            raise Exception(f'Unmapped builtin type {dt.standard_name}')
        return _builtins_to_argclass[dt.standard_name]
    raise Exception(f'Unhandled data type category {dt.category}')

class ArgAssigner:
    '''
    Provides the next argument location assignment based on its ArgClass
    and encapsulates the current state of available locations based on
    progression of parameters from left to right.
    '''
    def __init__(self) -> None:
        self._next_sse_regnum = 0

    def assign_locations(self, args:List[ArgClass]) -> List[Location]:
        '''
        Convert the list of argument classes into their corresponding locations
        according to the System V x64 ABI
        '''
        return [self._next_location(x) for x in args]

    def _next_location(self, argclass:ArgClass):
        '''Returns the location of the next argument (in left-to-right order)'''
        if argclass == ArgClass.SSE:
            return self._next_SSE()
        raise Exception(f'Unhandled ArgClass {argclass}')

    def _next_SSE(self) -> Location:
        '''Return the location for the next SSE parameter'''
        if self._next_sse_regnum <= 7:
            xmm_loc = Location(LocationType.Register, f'XMM{self._next_sse_regnum}')
            self._next_sse_regnum += 1
            return xmm_loc
        # CLS: if we're out of XMM regs I think we revert to the stack,
        # maybe confirm this first with a real example...
        raise Exception(f'Out of XMM registers - confirm we revert to stack')
        return self._next_stack()

    def _next_stack(self) -> Location:
        '''Returns the next stack location'''
        raise Exception(f'TODO: implement _next_stack')

def get_sysv_calling_conv(param_types:List[DataType]) -> List[Location]:
    '''
    Applies the System V x64 calling convention for the given function parameter
    list and returns a corresponding list of locations at which each parameter will
    be passed
    '''
    # this function encapsulates the entire mapping process for a single function,
    # so we can easily start with a clean state here but allow the state to persist
    # for all function arguments so we get a proper mapping

    # 1. classify each argument type
    # 2. assign argument location left-to-right based on classification

    arg_classes = [type_to_argclass(dt) for dt in param_types]
    return ArgAssigner().assign_locations(arg_classes)

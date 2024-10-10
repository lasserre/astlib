from enum import Enum
from typing import List

from varlib.datatype import *
from varlib.location import Location, LocationType

# CLS: wasn't sure the best place for this but I need to be able to reuse it
# in various places so it makes sense to come along with dwarflib right now

class ArgClass(Enum):
    INTEGER = 1
    SSE = 2
    SSEUP = 3
    X87 = 4
    X87UP = 5
    COMPLEX_X87 = 6
    NO_CLASS = 7
    MEMORY = 8

_builtins_to_argclass = {
    'double': ArgClass.SSE,
    'float': ArgClass.SSE,

    # CLS: wait to define long double/float10 - need to test with real cases
    # 'long double': None,
    # 'float10': None,

    'uint8_t': ArgClass.INTEGER,
    'uint16_t': ArgClass.INTEGER,
    'uint32_t': ArgClass.INTEGER,
    'uint64_t': ArgClass.INTEGER,
    'int8_t': ArgClass.INTEGER,
    'int16_t': ArgClass.INTEGER,
    'int32_t': ArgClass.INTEGER,
    'int64_t': ArgClass.INTEGER,

    # CLS: I think these are NOT __m128, but __int128, wait
    # for a test case to confirm
    # '__uint128_t': ArgClass.INTEGER,
    # '__int128_t': ArgClass.INTEGER,
}

def has_unaligned_fields(st:StructType):
    # From #1 in section 3.2.3 under aggregate/union types, the wording
    # "contains unaligned fields" I THINK means that any of the fields
    # are not 8-byte aligned
    # TODO: test this out and confirm
    for offset in st.layout:
        if offset % 8 != 0:
            return True
    return False


def type_to_argclass(dt:DataType) -> ArgClass:
    if dt.category == DataTypeCategories.BuiltIn:
        if dt.standard_name not in _builtins_to_argclass:
            raise Exception(f'Unmapped builtin type {dt.standard_name}')
        return _builtins_to_argclass[dt.standard_name]
    elif dt.category == DataTypeCategories.Pointer:
        return ArgClass.INTEGER
    elif dt.category == DataTypeCategories.Enum:
        return ArgClass.INTEGER
    elif dt.category == DataTypeCategories.Struct:
        # TODO: temp for verification...
        if has_unaligned_fields(dt):
            raise Exception(f'Check my assumption on what unaligned fields means!')

        # NOTE: ignoring the #2) note on C++ objects because we're not doing
        # those right now...

        # TODO: temp for verification...
        if dt.size > 32 and dt.size < 64:
            raise Exception(f'Check this - does GCC push this to MEMORY class or still apply algorithm?')

        if dt.size > 32 or has_unaligned_fields(dt):
            return ArgClass.MEMORY
        elif dt.size > 8:
            # this was very helpful...the standard is confusing and doesn't have enough explanation:
            # https://stackoverflow.com/questions/65992291/x86-64-system-v-abi-argument-classification-for-parameter-passing

            # essentially, we need to account for every eightbyte in the structure, recursing
            # down to "terminal nodes" and applying the post merger cleanup to get the final result
            # (remember, this only happens for structs > 32 bytes, so shouldn't take forever...)

            ##############################################
            # TODO: pick up with algorithm here...
            ##############################################
            # --> have the structure return a list of classes
            # for each of its eightbytes
            # --> this is easy to combine with other fields recursively
            # --> no offset needed, everything is in eightbytes...at the
            # top level then you know each offset
            ##############################################
            print(f'Struct category with size > 8')

            # TODO: pick up here...looks like basically if anything is MEMORY
            # it "taints" the whole structure to be in memory... (remember these are small structs)
            # - make this simple, test it out...try and catch the various cases and spot check
            for offset, field in dt.layout.items():
                field_argclass = type_to_argclass(field.dtype)
                # if field.size


            # (if it's too weird/tricky to ask for a specific offset of a struct as we recurse,
            # we can implement this iteratively instead...)

            pass
        else:
            raise Exception(f'Handle other struct case')

    raise Exception(f'Unhandled data type category {dt.category}')

class ArgAssigner:
    '''
    Provides the next argument location assignment based on its ArgClass
    and encapsulates the current state of available locations based on
    progression of parameters from left to right.
    '''
    def __init__(self) -> None:
        self._next_sse_regnum = 0
        self._next_integer_locs = [
            Location(LocationType.Register, 'rdi'),
            Location(LocationType.Register, 'rsi'),
            Location(LocationType.Register, 'rdx'),
            Location(LocationType.Register, 'rcx'),
            Location(LocationType.Register, 'r8'),
            Location(LocationType.Register, 'r9'),
        ]

    def assign_locations(self, param_types:List[DataType]) -> List[Location]:
        '''
        Convert the list of argument classes into their corresponding locations
        according to the System V x64 ABI
        '''
        arg_classes = [type_to_argclass(dt) for dt in param_types]
        arg_locs = [self._next_location(x) for x in arg_classes]

        next_stack_offset = 8
        for i, stack_loc in enumerate(arg_locs):
            if stack_loc.loc_type != LocationType.Stack:
                continue
            stack_loc.offset = next_stack_offset

            # calculate next stack offset based on size of data aligned to 8B
            data_size = param_types[i].size
            if data_size % 8 != 0:
                # align to 8B boundary
                data_size = (data_size/8 + 1) * 8
            next_stack_offset += data_size

        return arg_locs

    def _next_location(self, argclass:ArgClass):
        '''Returns the location of the next argument (in left-to-right order)'''
        if argclass == ArgClass.SSE:
            return self._next_SSE()
        elif argclass == ArgClass.INTEGER:
            return self._next_INTEGER()
        raise Exception(f'Unhandled ArgClass {argclass}')

    def _next_INTEGER(self) -> Location:
        if self._next_integer_locs:
            return self._next_integer_locs.pop(0)
        return self._next_stack()

    def _next_SSE(self) -> Location:
        '''Return the location for the next SSE parameter'''
        if self._next_sse_regnum <= 7:
            xmm_loc = Location(LocationType.Register, f'XMM{self._next_sse_regnum}')
            self._next_sse_regnum += 1
            return xmm_loc
        return self._next_stack()

    def _next_stack(self) -> Location:
        '''Returns the next stack location'''
        # NO OFFSET YET - these actually get pushed in reverse order so we assign offsets last
        return Location(LocationType.Stack)

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

    return ArgAssigner().assign_locations(param_types)

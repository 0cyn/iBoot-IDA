from enum import Enum, IntEnum
from abc import ABC, abstractmethod, abstractstaticmethod, abstractproperty


class Bitness(IntEnum):
    Bitness32 = 1
    Bitness64 = 2


class SearchDirection(IntEnum):
    UP = 0
    DOWN = 1


class Field:
    def __init__(self, name, ftype, nbytes):
        self.name = name
        self.ftype = ftype
        self.nbytes = nbytes


class Struct:
    def __init__(self, name, fields):
        self.name = name
        self.fields = fields


class SegmentType(Enum):
    CODE = 0
    STACK = 1


class ProcessorType(Enum):
    ARM32 = 0
    ARM64 = 1


class DisassemblerType(Enum):
    IDA = 0


class Segment:
    def __init__(self, name, start, size, seg_type: SegmentType, seg_bitness: Bitness):
        self.name = name
        self.start = start
        self.end = start + size
        self.size = size
        self.seg_type = seg_type
        self.seg_bitness = seg_bitness


class DisassemblerFile(ABC):
    @abstractmethod
    def __init__(self, fd):
        """
        Create a new DisassemblerFile

        :param fd: File-like object
        """

    @abstractmethod
    def load_ptr_from(self, location) -> int:
        """
        Load a pointer of platform_pointer_size size

        :param location: Location to load pointer from
        :return:
        """


class API(ABC):

    @staticmethod
    @abstractmethod
    def api_name() -> str:
        """

        :return:
        """

    @staticmethod
    @abstractmethod
    def bad_address() -> int:
        """Returns the BAD_ADDRESS value for the disassembler

        :return: Bad Address
        """

    @staticmethod
    @abstractmethod
    def get_function(location: int) -> int:
        """Get the address of the function start `location` is located in.

        :return: Function start
        """

    @staticmethod
    @abstractmethod
    def get_disasm_file(fd) -> DisassemblerFile:
        """Generates a Disassembler Subclassed file for the respective disassembler from a file-like object.

        :param fd:
        :return:
        """

    @staticmethod
    @abstractmethod
    def set_processor_type(type: ProcessorType) -> None:
        """Set the processor type for the file

        :param type: Processor Type
        """

    @staticmethod
    @abstractmethod
    def create_segment(segment: Segment) -> None:
        """Create a segment

        :param segment: segment to add
        :return:
        """

    @staticmethod
    @abstractmethod
    def function_addresses() -> list:
        """List of function addresses in the program

        :return:
        """

    @staticmethod
    @abstractmethod
    def get_disasm(location: int) -> str:
        """Get a string containing disassembly at the requested address

        :param location:
        :return:
        """

    @staticmethod
    @abstractmethod
    def rebase_to(delta: int) -> None:
        """Rebase the entire program by delta bytes

        :param delta:
        :return:
        """

    @staticmethod
    @abstractmethod
    def xrefs_to(function_ea: int) -> list:
        """List of cross-references to function_ea

        :return:
        """

    @staticmethod
    @abstractmethod
    def get_function_name(location: int) -> None:
        """Get the name (if it exists) of the function at location

        :return:
        """

    @staticmethod
    @abstractmethod
    def copy_da_file_to_segment(file: DisassemblerFile, segment: Segment, file_location: int) -> None:
        """
        Copy a Disassembler File's bytes into a segment; Load it

        :param file_location:
        :param file:
        :param segment:
        :return:
        """

    @staticmethod
    @abstractmethod
    def add_struct(struct: Struct) -> None:
        """Add a struct to the table

        :param struct: Struct to add
        """

    @staticmethod
    @abstractmethod
    def add_name(location: int, name: str) -> None:
        """
        Add a name for an address

        :param location: Address
        :param name: Name to add
        """

    @staticmethod
    @abstractmethod
    def add_entry_point(location: int, name: str) -> None:
        """
        Add an entry point in the program

        :param location: Address
        :param name: Name of the entry point
        :return:
        """

    @staticmethod
    @abstractmethod
    def search_binary(binary: str, start: int, end: int, direction: SearchDirection) -> int:
        """Perform a binary search

        :param binary:
        :param start:
        :param end:
        :param direction:
        :return: Location
        """

    @staticmethod
    @abstractmethod
    def search_text(text: str, start: int, end: int, direction: SearchDirection) -> int:
        """Perform a text search

        :param text:
        :param start:
        :param end:
        :param direction:
        :return:
        """

    @staticmethod
    @abstractmethod
    def ask(text) -> bool:
        """
        Ask the user a question and get a yes/no answer

        :param text: Question
        :return: Boolean indicating yes(True) or no(False)
        """

    @staticmethod
    @abstractmethod
    def analyze(start: int, end: int) -> None:
        """
        in IDEs that supoort/require it, Auto-Analyze a region of code

        wait to return until finished

        :param start: Starting Address
        :param end: Ending address
        :return: Returns nothing once finished
        """

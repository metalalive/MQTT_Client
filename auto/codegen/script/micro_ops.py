import os
from typing import List

class MicroOperations:

    middleware_sys_fn_map = None

    def _strlen(inbytes):
        nbytes = 0
        if(inbytes is not None):
            if(isinstance(inbytes , list) is True):
                inbytes = ''.join(inbytes)
            nbytes = len(inbytes)
        return nbytes

    def _num_list_item(l : List) -> int:
        return len(l)

    def _file_dump_hex(filepath):
        out = None
        with open(filepath, "rb") as f:
            out = f.read()
        out = [hex(char) for char in out]
        return out

    def _gen_C_char_array(hex_in) -> str:
        out = hex_in
        if(isinstance(out, list)):
            out = ','.join(out)
        #### print("[_file_dump_hex]: first 6 bytes : "+ str(out[:30])  )
        return out

    def _map_C_sys_fn(in_list):
        new_list = []
        fn_map = MicroOperations.middleware_sys_fn_map
        if(fn_map and in_list):
            for idx in range(len(in_list)):
                for jdx in in_list[idx]:
                    for kdx in fn_map[0]:
                        if(jdx == kdx):
                            new_list.append(''.join(in_list[idx][jdx]))
                            for mdx in range(len(in_list[idx][jdx])):
                                try:
                                    new_list.append( fn_map[0][kdx][mdx] )
                                    ## in_list[idx][jdx].append( fn_map[0][kdx][mdx] )
                                except IndexError as e:
                                    pass
                            new_list[1] = ''.join(new_list[1:])
                            while len(new_list) > 2:
                                new_list.pop()
                            new_list.insert(1, " ")
                            in_list[idx][jdx].clear()
                            in_list[idx][jdx] = ''.join(new_list)
                            new_list.clear()

            new_list.clear()
            for idx in range(len(in_list)):
                for fn_name in in_list[idx]:
                    tmp = ''.join(in_list[idx][fn_name])
                    new_list.append(tmp)
                in_list[idx].clear()

        return new_list
#### end of _map_C_sys_fn

    def _list_add_pattern_before(in_list, pattern):
        idx = 0
        while idx < len(in_list):
            in_list.insert(idx, pattern)
            idx += 2
        return in_list

    def _list_append_pattern(in_list, pattern):
        idx = 0
        while idx < len(in_list):
            in_list.insert(idx + 1, pattern)
            idx += 2
        return in_list

    def _gen_C_define(in_list):
        in_list = MicroOperations._list_add_pattern_before(in_list, "\n#define ")
        in_list.append("\n")
        return in_list

    def _gen_C_include(in_list):
        in_list = MicroOperations._list_add_pattern_before(in_list, "\n#include ")
        in_list.append("\n")
        return in_list

    def _wrap_quote(in_str):
        if(isinstance(in_str, str)):
            in_str = ''.join(["\"", in_str,"\""])
        return in_str

    def _list_append_semicolon(in_list):
        return MicroOperations._list_append_pattern(in_list, ";")

    def _list_append_whitespace(in_list):
        return MicroOperations._list_append_pattern(in_list, " ")

    def _convert_BCD(s: str) -> str:
        if(isinstance(int(s), int)):
            s = ''.join(['0x', s])
        return s

    def _num_to_str(in_num):
        return str(in_num)

    def _ipaddr_to_hex(s:str) -> List[str]:
        # Default return for non-IP or invalid IP
        default_return = ['0','0','0','0']

        if not isinstance(s, str):
            return default_return

        parts = s.split('.')
        if len(parts) != 4:
            return default_return

        hex_parts = []
        for part in parts:
            try:
                num = int(part)
                if not (0 <= num <= 255):
                    return default_return # Not a valid octet (0-255)
                hex_parts.append(hex(num))
            except ValueError:
                return default_return # Not a valid number in part

        return hex_parts

    fn_map = {
        "numToStr"       : _num_to_str,
        "strlen"         : _strlen,
        "numlistitem"    : _num_list_item,
        "filelen"        : os.path.getsize,
        "filedumphex"    : _file_dump_hex,
        "genCcharArray"  : _gen_C_char_array,
        "sysFnMap"       : _map_C_sys_fn,
        "genCdefine"     : _gen_C_define,
        "getCinclude"    : _gen_C_include,
        "wrapQuote"      : _wrap_quote,
        "convertBCD"     : _convert_BCD,
        "ipToHexChar"    : _ipaddr_to_hex,
        "ListAppendSemicolon"  : _list_append_semicolon,
        "ListAppendWhitespace" : _list_append_whitespace,
    }

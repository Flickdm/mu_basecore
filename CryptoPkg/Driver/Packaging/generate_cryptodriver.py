##
# This file creates three files for the CryptoDriver. These files are placed inside the CryptoPkg itself.
# - The Crypto.c file that populates the protocol struct
# - The Crypto.h file which contains defintions for the protocol itself and the functions
# - The Pcd.inc.dec file which has a list of all the PCD's the will get defined. This is meant to be copied into the CryptoPkg.dec
# - The CryptoPkg.inc.dsc which is included in the DSC that configures that various flavors
#            (it's split up into different flavors for easier including by other platforms)
# - The Crypto.inc.inf file which ic meant to be copied into an inf file (CryptoSmm.inf for example)
#
# If you wish to add or tweak a flavor, this is the place to do it
#
# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import glob
import shutil
import argparse
import datetime
from enum import Enum

SCRIPT_DIR = os.path.dirname(__file__)
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(SCRIPT_DIR)))
REL_PATH = os.path.relpath(__file__, ROOT_DIR)

DEFAULT_OUTPUT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "Bin"))

BASE_TEMPLATE_REPLACEMENT_TAG = "__REPLACEMENT_TAG__ - Autogenerated contents go here."


def main():
    # get command line options
    options = ParseCommandLineOptions()
    # Read in all the functions from the Crypto and Tls headers
    crypto_functions = read_basecryptlib_and_tlslib(options)
    # generate the requested files
    if options.c_file:
        get_crypto_c(options, crypto_functions)
        if options.copy:
            # TODO: define this somewhere globally
            c_file_path = os.path.join(options.out_dir, "temp_Crypto.c")
            shutil.copyfile(c_file_path, os.path.join(ROOT_DIR, "CryptoPkg", "Driver", "Crypto.c"))
    if options.h_file:
        get_crypto_h(options, crypto_functions)
        if options.copy:
            # TODO: define this somewhere globally
            h_file_path = os.path.join(options.out_dir, "temp_Crypto.h")
            shutil.copyfile(h_file_path, os.path.join(ROOT_DIR, "CryptoPkg", "Include", "Protocol", "Crypto.h"))
    if options.p_file:
        get_crypto_pcds(options, crypto_functions)
    if options.d_file:
        get_crypto_dsc(options, crypto_functions)
    if options.i_file:
        get_crypto_inf(options, crypto_functions)
    if options.l_file:
        get_crypto_lib_c(options, crypto_functions)
        if options.copy:
            # TODO: define this somewhere globally
            c_lib_file_path = os.path.join(options.out_dir, "temp_CryptLib.c")
            shutil.copyfile(c_lib_file_path, os.path.join(ROOT_DIR, "CryptoPkg", "Library", "BaseCryptLibOnProtocolPpi", "CryptLib.c"))

    generate_platform_files()   # TODO: Refactor. Copied from separate script.

    print("Success. Thanks for playing :)")


def ParseCommandLineOptions():
    ''' parse arguments '''
    def validate_abs_path(path_arg: str):
        if not os.path.exists(path_arg):
            raise ValueError(f"path '{path_arg}' is not valid")
        return os.path.abspath(path_arg)

    ParserObj = argparse.ArgumentParser()
    ParserObj.add_argument("-v", "--verbose", dest="verbose", default=False, action='store_true',
                           help="Logs verbosely")
    ParserObj.add_argument("-index", "--pcd-index", dest="pcd_index", default="0x03",
                           help="The hex index where the PCD will start (default 0x03")
    ParserObj.add_argument("-o", "--out", dest="out_dir", default=DEFAULT_OUTPUT_DIR,
                           help="The directory where the files are stored, relative to this script")
    ParserObj.add_argument("-in", "--template", dest="in_dir", default="./",
                           help="The directory where the template files are stored, relative to this script")
    ParserObj.add_argument("--no-copy", dest="copy", default=True, action='store_false',
                           help="Don't copy the created files into the correct location (Crypto.c, crypto.h, CryptLib.c)")
    ParserObj.add_argument("--enable-comp-time", "-ctc", dest="ctc", default=False, action='store_true',
                           help="Enable Compile Time check for generated library files")
    ParserObj.add_argument("--disable-null-only", dest="eno", default=True, action='store_false',
                           help="Disable config to use Nulls for protocol instead of unsupported function")
    # parse the args
    options = ParserObj.parse_args()

    # Set individual files for back compat with old script.
    options.p_file = True
    options.h_file = True
    options.c_file = True
    options.d_file = True
    options.i_file = True
    options.l_file = True

    # resolve the paths against our current directory
    options.out_dir = os.path.abspath(os.path.join(SCRIPT_DIR, options.out_dir))
    options.in_dir = os.path.abspath(os.path.join(SCRIPT_DIR, options.in_dir))

    # make sure our output and input paths are real places
    if not os.path.exists(options.out_dir):
        raise FileNotFoundError(f"Make sure your output directory exists: {options.out_dir}")
    if not os.path.exists(options.in_dir):
        raise FileNotFoundError(f"Make sure your output directory exists: {options.in_dir}")

    if options.verbose:
        print(f"Writing output to: {options.out_dir}")

    return options


# This is the place to define the flavors
def get_flavors():
    '''
    The flavors of shared crypto to use.
    families are the types to turn on (SHA1 for example), it must be uppercase
    individuals are the functions to turn on and must be spelled correctly
    exclude are the functions that will always off and take precedence
    guid is the guid to use for the binaries that get generated
            the last two digits will be used to tell what type of binary it is (PEI, DXE, SMM, Standalone MM, etc)
    '''
    return {
        "TINY_SHA": {
            "families": ["SHA1", "SHA256", "SHA384"],
            "individuals": ["Pkcs5HashPassword"],
            "exclude": ["Sha256HashAll", "Sha1HashAll"],
            "guid": "e6ed744a-8db0-42b8-a507-8909782ed200"
        },
        "MINIMAL_SHA_SM3": {
            "families": ["HMACSHA256", "SHA1", "SHA256", "SHA384", "SHA512", "SM3"],
            "individuals": ["Pkcs5HashPassword"],
            "exclude": ["Sha256HashAll", "Sha1HashAll"],
            "guid": "6d653b3b-0654-4eec-8ab3-183a3e061400"
        },
        "SMALL_SHA_RSA": {
            "families": ["HMACSHA256", "SHA1", "SHA256", "SHA384", "SHA512", "SM3"],
            "individuals": ["RsaPkcs1Verify", "RsaNew", "RsaFree", "RsaSetKey", "Pkcs5HashPassword", "RsaPssSign", "RsaPssVerify"],
            "exclude": ["Sha256HashAll", "Sha1HashAll"],
            "guid": "d9a75606-caba-4aa0-80a6-591852335400"
        },
        "STANDARD": {
            "families": ["HMACSHA256", "PKCS", "SHA1", "SHA256", "RANDOM", "TLS", "TLSGET", "TLSSET"],
            "individuals": ["RsaPkcs1Verify", "RsaNew", "RsaFree", "RsaGetPublicKeyFromX509", "X509GetSubjectName", "X509GetCommonName", "X509GetOrganizationName", "X509GetTBSCert", "RsaPssSign", "RsaPssVerify"],
            "exclude": ["Sha1HashAll", "Sha256HashAll", "Pkcs7Sign", "Pkcs7GetCertificatesList", "ImageTimestampVerify"],
            "guid": "bdee011f-87f2-4a7f-bc5e-44b6b61fef00"
        }
    }


def read_header_file(options, path):
    ''' reads a header file and pulls out the function definitions'''
    if not path.lower().endswith(".h"):
        raise ValueError("I cannot parse a non header file")
    header_file = open(path, 'r')
    # define the modes of our simple state machine
    modes = Enum("HEADER_PARSE_MODES", [
                 "COMMENT", "RETURN_TYPE", "EFI_API", "NAME", "PARAMS", "FINISHED", "UNKNOWN"])
    mode = modes.COMMENT
    file_name = os.path.basename(path)

    class crypto_function:
        ''' creates a blank function object'''

        def __init__(self):
            self.comment = []  # the comments
            self.name = ""  # the name of the funtion
            self.return_type = "VOID"
            self.params = []
            self.type = None  # PKCS, SHA1, PKCS for example
            self.source = file_name
            self.disabled = False
            self.line_no = 0  # this is the line number that the name comes from

        def __repr__(self):
            return self.name

        def get_raw_repr(self):
            ''' this returns what was in the BaseCryptLib.h '''
            lines = []
            if self.disabled:
                lines.append("#ifdef 0 // Disabled via an ifdef")
            lines.extend(self.comment)
            lines.append(self.return_type)
            lines.append("EFI_API")
            lines.append(f"{self.name} ( // From {self.source}:{self.line_no}")
            lines.extend(self.params)
            lines.append("  );")
            if self.disabled:
                lines.append("#endif // Disabled via an ifdef")

            return "\n".join(lines)

        def set_return_type_if_valid(self, line: str):
            ''' Sets the return type to what is passed in, if it's a valid return type '''
            line = line.upper()
            if line not in ["VOID *", "VOID*", "BOOLEAN", "UINTN", "VOID", "RETURN_STATUS", "UINT8", "UINT16", "UINT32", "INTN", "EFI_STATUS"]:
                return False
            self.return_type = line
            return True

        @classmethod
        def valid_types(cls):
            ''' the valid types that the function can be '''
            return ["HMACSHA256", "HMACSHA384", "PKCS", "DH", "RANDOM", "RSA", "SHA1",
                    "SHA256", "SHA384", "SHA512", "PARALLELHASH256", "AEADAESGCM", "X509", "ASN1", "BIGNUM", "TDES", "AES", "ARC4", "SM3", "HKDF", "TLS", "TLSSET", "TLSGET", "EC"]

        def get_escaped_name(self):
            '''
            get the name seperated by _ in all upper case
            example: HmacSha1New -> HMAC_SHA1_NEW
            '''
            if self.name is None or len(self.name) == 0:
                return "???"
            escape_name = ""
            last_char_upper = True
            # iterate through each character in the name
            for char in self.name:
                if char == ' ':  # we shouldn't have any spaces here, but just in case
                    char = '_'
                cur_char_upper = char.isupper()
                # if this is an uppercase letter and the last one was lower
                if not last_char_upper and cur_char_upper:
                    escape_name += "_"
                escape_name += char.upper()
                last_char_upper = cur_char_upper
            return escape_name

        def get_protocoled_name(self):
            ''' Get the protocoled version of the name '''
            return "EDKII_CRYPTO_" + self.get_escaped_name()

        def get_default_value(self):
            ''' returns the default value of this function based on the return type '''
            if self.return_type == "BOOLEAN":
                return "FALSE"
            if self.return_type == "VOID*" or self.return_type == "VOID *":
                return "NULL"
            return "0"

        def get_params_tuple(self):
            ''' get the parameters as a tuple. If there aren't any, it returns ["VOID"] '''
            param_names = list(map(lambda x: x.strip(",").strip().replace(" OPTIONAL", "").strip("[]").strip().split()[-1].strip("*").strip(","), self.params))
            if len(param_names) == 1 and param_names[0] == 'VOID':
                return []
            return param_names

        def get_params_formatted(self):
            ''' get the parameters seperated by commas wrapped in parentheses'''
            params = self.get_params_tuple()
            if len(params) > 0 and params[-1] == "...":
                params[-1] = "Args"
            return "(" + ", ".join(params) + ")"

        def get_pcd_name(self):
            ''' Get the PCD name with the TokenSpaceGuid attached '''
            return "gEfiCryptoPkgTokenSpaceGuid.PcdCryptoService"+self.name

        def get_type(self):
            ''' Based on the name, get the type '''
            if self.disabled:
                return None
            if self.name == "":
                return None
            valid_types = self.valid_types()
            name = self.name.upper()
            if name == "VERIFYEKUSINPKCS7SIGNATURE" or name == "AUTHENTICODEVERIFY" or name == "IMAGETIMESTAMPVERIFY":
                name = "PKCS7"+name
            # filter them so it's only things that start with that
            possible_types = filter(lambda x: name.startswith(x), valid_types)
            self.type = ""
            for possible_type in possible_types:
                self.type = possible_type if len(possible_type) > len(self.type) else self.type
            if self.type == "":
                raise ValueError(f"{self.source}:{self.line_no} Unknown type: {name}")

            return self.type

    cur_function = crypto_function()
    all_functions = []
    ifdef_level = 0
    # iterate through each line in the header
    for index, line in enumerate(header_file.readlines()):
        sline = line.strip()
        line = line.strip("\n")
        if sline.startswith("#ifdef"):
            ifdef_level += 1
            continue
        if sline.startswith("#endif"):
            ifdef_level -= 1
            continue
        if len(sline) == 0 or sline.startswith("#") or sline.startswith("//"):
            continue
        if ifdef_level > 0:
            cur_function.disabled = True
        if sline.startswith("/**"):  # if we find a comment
            cur_function.comment = [line, ]
            mode = modes.COMMENT
        # if we find the end of a comment
        elif sline.endswith("**/") and mode == modes.COMMENT:
            mode = modes.RETURN_TYPE
            cur_function.comment.append(line)
        elif mode == modes.COMMENT:  # if we're currently in comment mode
            cur_function.comment.append(line)
        # if we find the end of the definition
        elif mode == modes.PARAMS and sline.endswith(";"):
            all_functions.append(cur_function)
            cur_function = crypto_function()
        elif mode == modes.PARAMS:  # if we're looking for parameters
            cur_function.params.append(line)
        elif mode == modes.RETURN_TYPE:  # if we're looking for the return type
            if not cur_function.set_return_type_if_valid(sline):
                if options.verbose:
                    print(f"{file_name}:{index} Invalid Return type: {sline}")
                mode = modes.UNKNOWN
            else:
                mode = modes.EFI_API
        elif mode == modes.EFI_API:  # make sure EFIAPI is a thing we find
            mode = modes.NAME if sline == "EFIAPI" else modes.UNKNOWN
        elif mode == modes.NAME:  # if we're looking for the name of the function
            if not sline.endswith("(") != 0:
                mode = modes.UNKNOWN
            else:
                cur_function.line_no = index
                cur_function.name = sline.strip("(").strip()
                mode = modes.PARAMS

    if options.verbose:
        print(f"Found {len(all_functions)} functions from {file_name}")
    return all_functions


def read_basecryptlib_and_tlslib(options):
    ''' reads in the BaseCryptLib and TlsLib header to generate the protocol '''
    # first we must find the BaseCryptLib and TlsLib
    # we can assume that it's located in ..\..\Include\Library\BaseCryptLib.h
    library_dir = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", "Include", "Library"))
    if options.verbose:
        print(f"Looking for BaseCryptLib.h and TlsLib.h at: {library_dir}")
    # check that the directory exists
    if not os.path.exists(library_dir):
        raise FileNotFoundError("Unable to find BaseCryptLib.h")
    crypt_h_path = os.path.join(library_dir, "BaseCryptLib.h")
    tls_h_path = os.path.join(library_dir, "TlsLib.h")
    # we need somewhere to store the functions we found
    all_functions = []
    all_functions.extend(read_header_file(options, crypt_h_path))
    all_functions.extend(read_header_file(options, tls_h_path))

    return all_functions


def sort_functions(functions):
    ''' sorts the crypto/tls functions according to type '''
    if len(functions) == 0:
        return []
    sorted_functions = []
    for valid_type in functions[0].valid_types():
        funcs_of_type = list(filter(lambda x: x.get_type() == valid_type, functions))
        sorted_functions.append((valid_type, funcs_of_type))
    return sorted_functions


def get_replacement_chunk(replacement_lines, output_filename, comment="//"):
    chunk = [f"{comment} ****************************************************************************",
             f"{comment} AUTOGENERATED BY " + REL_PATH,
             f"{comment} AUTOGENED AS {output_filename}",
             f"{comment} DO NOT MODIFY",
             f"{comment} GENERATED ON: " + str(datetime.datetime.now()),
             ""     # Newline
    ]

    # Add in the new strings
    chunk.extend(replacement_lines)

    # Add the ending
    chunk.extend([f"{comment} AUTOGEN ENDS",
                  f"{comment} ****************************************************************************"
    ])

    return chunk


def generate_file_replacement(replacement_lines, input_path, output_filename, options, comment="//"):
    ''' generates a file at the output path, taking in input from the input path '''

    input_data = ""
    if input_path is not None:
        input_file_path = os.path.abspath(os.path.join(options.in_dir, input_path))
        with open(input_file_path, 'r') as in_file:
            input_data = in_file.read()
        if len(input_data) == 0:
            raise RuntimeError(f"file '{input_path}' could not be read")

    output_chunk = "\n".join(get_replacement_chunk(replacement_lines, output_filename, comment))
    if len(input_data) == 0:
        output_data = output_chunk + "\n"
    else:
        output_data = input_data.replace(f"{comment} {BASE_TEMPLATE_REPLACEMENT_TAG}", output_chunk)

    # write it out
    output_path = os.path.join(options.out_dir, output_filename)
    with open(output_path, 'w') as out_file:
        out_file.write(output_data)

    if options.verbose:
        print(f"Outputted to {output_path}")


def get_crypto_c(options, functions):
    ''' generates the c file that populates the struct defined by crypto.h '''
    print("Generating C file")
    lines = []

    sorted_functions = sort_functions(functions)

    # generate the function bodies
    if not options.eno:
        for valid_type, funcs in sorted_functions:
            lines.append("// =============================================================================")
            lines.append(f"//     {valid_type} functions")
            lines.append("// =============================================================================")
            if len(funcs) > 0:
                lines.append("")
            for func in funcs:
                lines.extend(func.comment)
                lines.append(f"// See {func.source}:{func.line_no}")
                lines.append(func.return_type)
                lines.append("EFIAPI")
                lines.append(f"CryptoService{func.name} (")
                lines.extend(func.params if len(func.params) > 0 else ["  VOID", ])
                lines.append("  )")
                lines.append("{")
                params = func.get_params_tuple()
                if len(params) > 0 and params[-1] == "...":
                    lines.append("  VA_LIST  Args;")
                    lines.append("  BOOLEAN  Result;")
                    lines.append("")
                    lines.append(f"  VA_START (Args, {params[0]});")
                    lines.append(f"  Result = CryptoService{func.name} {func.get_params_formatted()};")
                    lines.append("  VA_END (Args);")
                    lines.append("  return Result;")
                elif (func.return_type == "VOID"):
                    lines.append(f"  {func.name} {func.get_params_formatted()};")
                else:
                    lines.append(f"  return {func.name} {func.get_params_formatted()};")
                lines.append("}")

    # Generate the struct
    lines.append("const EDKII_CRYPTO_PROTOCOL  mEdkiiCrypto = {")
    lines.append("  /// Version")
    lines.append("  CryptoServiceGetCryptoVersion,")
    for valid_type, funcs in sorted_functions:
        lines.append(f"  // {valid_type} functions")
        for func in funcs:
            if options.eno:
                lines.append(f" #if _PCD_VALUE_PcdCryptoService{func.name}")
            lines.append(f"  {func.name},")
            if options.eno:
                lines.append(" #else")
                lines.append("  NULL,")
                lines.append(" #endif")
    lines.append("};")

    generate_file_replacement(lines, "Crypto.template.c", "temp_Crypto.c", options)


def get_crypto_lib_c(options, functions):
    ''' generates the cryptlib.c file that forms the baseCryptlib implementation '''
    print("Generating C library file")

    lines = []
    sorted_functions = sort_functions(functions)
    # generate the function bodies
    for valid_type, funcs in sorted_functions:
        lines.append("// =============================================================================")
        lines.append(f"//     {valid_type} functions")
        lines.append("// =============================================================================")
        if len(funcs) > 0:
            lines.append("")
        for func in funcs:
            # add a macro that will turn this off if it's not enabled by PCD
            if options.ctc:
                lines.append(f"#if FixedPcdGetBool(PcdCryptoService{func.name})")
            lines.extend(func.comment)  # add the function comment
            lines.append(f"// See {func.source}:{func.line_no}")
            lines.append(func.return_type)  # return type
            lines.append("EFIAPI")
            lines.append(f"{func.name} (")
            lines.extend(func.params if len(func.params) > 0 else ["  VOID", ])
            lines.append("  )")
            lines.append("{")
            params = func.get_params_tuple()
            # we need to do something special for variable args
            if len(params) > 0 and params[-1] == "...":
                lines.append("  VA_LIST  Args;")
                lines.append("  BOOLEAN  Result;")
                lines.append("")
                lines.append(f"  VA_START (Args, {params[0]});")
                lines.append(f"  Result = {func.name}V {func.get_params_formatted()};")
                lines.append("  VA_END (Args);")
                lines.append("  return Result;")
            elif (func.return_type == "VOID"):
                lines.append(f"  CALL_VOID_CRYPTO_SERVICE ({func.name}, {func.get_params_formatted()});")
            else:
                lines.append(f"  CALL_CRYPTO_SERVICE ({func.name}, {func.get_params_formatted()}, {func.get_default_value()});")
            lines.append("}")
            lines.append("")
            # if we're doing compile time checking, have an else statement
            if options.ctc:
                lines.append("#else")
                # TODO generate something that will cause the linker to have errors?
                # we want to generate an error if someone includes this in their binary
                lines.append(f"#endif\n")

    generate_file_replacement(lines, "CryptLib.template.c", "temp_CryptLib.c", options)


def get_crypto_h(options, functions):
    ''' generates the crypto.h header file - this is the defintion of the protocol and it's struct'''
    print("Generating H file")

    lines = []
    sorted_functions = sort_functions(functions)

    # Generate the function prototypes
    for valid_type, funcs in sorted_functions:
        lines.append("// =============================================================================")
        lines.append(f"//     {valid_type} functions")
        lines.append("// =============================================================================")
        if len(funcs) > 0:
            lines.append("")
        for func in funcs:
            lines.extend(func.comment)
            lines.append(f"// FROM {func.source}:{func.line_no}")
            lines.append("typedef")
            lines.append(func.return_type)
            lines.append(f"(EFIAPI *{func.get_protocoled_name()})(")
            lines.extend(func.params if len(func.params) > 0 else ["  VOID", ])
            lines.append("  );")
            lines.append("")

    # generate the protocol struct
    lines.append("///\n/// EDK II Crypto Protocol\n///")
    lines.append("struct _EDKII_CRYPTO_PROTOCOL {")
    lines.append("  // VERSION")
    lines.append("  EDKII_CRYPTO_GET_VERSION                            GetVersion;")
    # generate the struct memebers
    for valid_type, funcs in sorted_functions:
        lines.append(f"  // {valid_type}")
        for func in funcs:
            member_name = func.get_protocoled_name().ljust(50)  # make sure they're all the same size
            lines.append(f"  {member_name}  {func.name};")
    lines.append("};")
    lines.append("")

    generate_file_replacement(lines, "Crypto.template.h", "temp_Crypto.h", options)


def get_crypto_dsc(options, functions):
    ''' generates the flavors into an includable dsc file '''
    print("Generating DSC file")
    flavors = get_flavors()
    lines = []
    # Check to make sure crypto services is configured
    lines.append("[Defines]")
    all_flavors = "ALL NONE PACKAGE "+" ".join(list(flavors))
    lines.append("!ifndef CRYPTO_SERVICES")
    lines.append(" DEFINE CRYPTO_SERVICES = PACKAGE")
    lines.append("!endif")
    lines.append(f"!if $(CRYPTO_SERVICES) IN \"{all_flavors}\"")
    lines.append(" # we don't have a problem")
    lines.append("!else")
    lines.append(f" !error CRYPTO_SERVICES must be set to one of {all_flavors}.")
    lines.append("!endif")
    lines.append("")
    # Set the default file guids
    lines.append("  DEFINE PEI_CRYPTO_DRIVER_FILE_GUID = d6f4500f-ad73-4368-9149-842c49f3aa00")
    lines.append("  DEFINE DXE_CRYPTO_DRIVER_FILE_GUID = 254e0f83-c675-4578-bc16-d44111c34e01")
    lines.append("  DEFINE SMM_CRYPTO_DRIVER_FILE_GUID = be5b74af-e07f-456b-a9e4-296c8fee9502")
    lines.append("  DEFINE STANDALONEMM_CRYPTO_DRIVER_FILE_GUID = 9c6714d5-33da-4488-9a9c-2a7070635140")
    lines.append("")

    # set the file guid for the different flavors
    for flavor in flavors:
        guid = flavors[flavor]["guid"]
        pei_guid = guid[0:-2] + '01'
        dxe_guid = guid[0:-2] + '02'
        smm_guid = guid[0:-2] + '03'
        standalone_mm_guid = guid[0:-2] + '04'
        lines.append(f"!if $(CRYPTO_SERVICES) == {flavor}")
        lines.append(f"  DEFINE PEI_CRYPTO_DRIVER_FILE_GUID = {pei_guid}")
        lines.append(f"  DEFINE DXE_CRYPTO_DRIVER_FILE_GUID = {dxe_guid}")
        lines.append(f"  DEFINE SMM_CRYPTO_DRIVER_FILE_GUID = {smm_guid}")
        lines.append(f"  DEFINE STANDALONEMM_CRYPTO_DRIVER_FILE_GUID = {standalone_mm_guid}")
        lines.append(f"!endif\n")

    # now set the PCDS
    lines.append("[PcdsFixedAtBuild]")
    # get the functions sorted into a row
    sorted_functions = sort_functions(functions)
    # first the all flavor
    lines.append("!if $(CRYPTO_SERVICES) IN \"PACKAGE ALL\"")
    for function in functions:
        if function.disabled:
            continue
        lines.append(f"  {function.get_pcd_name().ljust(70)}| TRUE")
    lines.append("!endif\n")
    # now we do the flavors
    for flavor in flavors:
        lines.append(f"!if $(CRYPTO_SERVICES) == {flavor}")
        families = flavors[flavor]["families"]
        lines.append("")
        exclude = flavors[flavor]["exclude"]

        flavor_lines = []

        # set families
        for sort_type, funcs in sorted_functions:
            if sort_type not in families:
                continue
            flavor_lines.append(f"# {sort_type} family")
            for function in funcs:
                if function.name not in exclude:
                    flavor_lines.append(f"  {function.get_pcd_name().ljust(70)}| TRUE")
        # set individuals
        indiv = flavors[flavor]["individuals"]
        flavor_lines.append("# Individuals")
        for function in functions:
            if function.name in indiv and function.name not in exclude:
                flavor_lines.append(f"  {function.get_pcd_name().ljust(70)}| TRUE")

        flavor_file = f"Crypto.pcd.{flavor}.inc.dsc"
        generate_file_replacement(flavor_lines, None, flavor_file, options, "#")
        lines.append(f"!include CryptoPkg/Driver/Bin/{flavor_file}")
        lines.append("!endif\n")

    generate_file_replacement(lines, None, "Crypto.inc.dsc", options, "#")


def get_crypto_pcds(options, functions):
    ''' Generates the PCDs to be included in a DEC file '''
    print("Generating PCD file")
    sorted_functions = sort_functions(functions)
    lines = []
    lines.append("[PcdsFixedAtBuild]")
    index = int(options.pcd_index, 16)
    for valid_type, funcs in sorted_functions:
        lines.append(f"# {valid_type}")
        for func in funcs:
            if func.disabled:
                continue
            lines.append(f"  {func.get_pcd_name()}|FALSE|BOOLEAN|{hex(index)}")
            index += 1

    generate_file_replacement(lines, None, "temp_crypto_pcd.inc.dec", options, "#")


def get_crypto_inf(options, functions):
    ''' Generates the list of PCD's to be included in an INF '''
    print("Generating INF file")
    lines = []
    lines.append("[Pcd]")
    for func in functions:
        if func.disabled:
            continue
        lines.append(f"  {func.get_pcd_name().ljust(50)} # CONSUMES")
    generate_file_replacement(lines, None, "temp_crypto_pcd.inc.inf", options, "#")


def generate_platform_files():
    class options():
        out_dir = DEFAULT_OUTPUT_DIR
        verbose = False
    flavors = get_flavors()
    phases = ["Pei", "Dxe", "Smm", "StandaloneMm"]
    # Arm is currently disabled
    arches = ["X64", "AARCH64", "IA32", ]  # "ARM"
    targets = ["DEBUG", "RELEASE"]

    # first we need to generate the INF files
    inf_files = []
    for flavor in flavors:
        for phase in phases:
            for target in targets:
                for arch in arches:
                    if arch == "ARM":
                        continue
                    if arch in ["ARM","AARCH64"] and phase == "Smm":
                        continue
                    if arch in ["ARM","IA32"] and phase == "StandaloneMm":
                        continue
                    inf_files.append((flavor, phase, target, arch))
    print(f"Generating {len(inf_files)} inf files")
    # first delete any files that we don't need
    inf_start = "CryptoDriverBin"
    delete_files_of_pattern(f"{inf_start}*.inf")
    dsc_ci_lines = []

    # generate the inf files that include the binary files from nuget
    for flavor, phase, target, arch in inf_files:
        inf_lines = []
        guid = flavors[flavor]["guid"]
        module_types = {
            "Dxe": "DXE_DRIVER",
            "Pei": "PEIM",
            "Smm": "DXE_SMM_DRIVER",
            "StandaloneMm": "MM_STANDALONE"
        }
        mod_type = module_types[phase]
        original_guid = guid
        if arch == "IA32":
            guid = guid[:-4] + "1000"
        elif arch == "X64":
            guid = guid[:-4] + "2000"
        elif arch == "ARM":
            guid = guid[:-4] + "3000"
        elif arch == "AARCH64":
            guid = guid[:-4] + "4000"

        if target == "RELEASE":
            guid = guid[:-3] + "E00"
        elif target == "DEBUG":
            guid = guid[:-3] + "D00"

        if phase == "Pei":
            guid = guid[:-2] + "10"
        elif phase == "Dxe":
            guid = guid[:-2] + "20"
        elif phase == "Smm":
            guid = guid[:-2] + "30"
        if len(guid) != len(original_guid):
            raise ValueError(
                f"{guid} is not long enough. {len(guid)} vs {len(original_guid)}")
        inf_lines.extend(["[Defines]",
                          "  INF_VERSION                    = 0x0001001B",
                          f"  BASE_NAME                      = BaseCryptoDriver{phase}{arch}",
                          "  MODULE_UNI_FILE                = Crypto.uni",
                          f"  FILE_GUID                      = {guid}",
                          f"  MODULE_TYPE                    = {mod_type}",
                          "  VERSION_STRING                 = 1.0",
                          "  PI_SPECIFICATION_VERSION       = 0x00010032",
                          f"  ENTRY_POINT                    = Crypto{phase}Entry"])
        inf_lines.append(f"\n[Binaries.{arch}]")
        inf_lines.append(
            f"  PE32|edk2-basecrypto-driver-bin_extdep/{flavor}/{target}/{arch}/Crypto{phase}.efi|{target}")
        depex_phase = phase.upper() if phase != "StandaloneMm" else "SMM"
        inf_lines.append(
            f"  {depex_phase}_DEPEX|edk2-basecrypto-driver-bin_extdep/{flavor}/{target}/Crypto{phase}.depex|{target}")
        inf_lines.append("\n[Packages]")
        inf_lines.append("  CryptoPkg/CryptoPkg.dec")
        inf_lines.append("")
        inf_lines.append("[Depex]")
        inf_lines.append("  TRUE")
        inf_filename = f"{inf_start}_{flavor}_{phase}_{target}_{arch}.inf"
        # Add to the CI
        dsc_ci_lines.append(f"[Components.{arch}]")
        dsc_ci_lines.append("  CryptoPkg/Driver/Bin/" + inf_filename)
        generate_file_replacement(
            inf_lines, None, inf_filename, options(), comment="#")

    # now we generate the CI DSC include
    generate_file_replacement(
        dsc_ci_lines, None, "CryptoPkg.ci.inc.dsc", options(), comment="#")

    # now we generate the DSC include
    # start with making sure variables are defined
    dsc_lines = []
    dsc_lines.append("# this is to be included by a platform :)")
    dsc_lines.append("[Defines]")
    all_flavors = "ALL "+" ".join(list(flavors))
    for phase in phases:
        phase = phase.upper()
        dsc_lines.append(f"!ifndef {phase}_CRYPTO_SERVICES")
        dsc_lines.append(f" !error Please define {phase}_CRYPTO_SERVICES")
        dsc_lines.append("!endif")
        dsc_lines.append(
            f"!if $({phase}_CRYPTO_SERVICES) IN \"{all_flavors}\"")
        dsc_lines.append(" # we don't have a problem")
        dsc_lines.append("!else")
        dsc_lines.append(
            f" !error CRYPTO_SERVICES must be set to one of {all_flavors}.")
        dsc_lines.append("!endif")
        dsc_lines.append(f"!ifndef {phase}_CRYPTO_ARCH")
        dsc_lines.append(
            f" !error Please define {phase}_CRYPTO_ARCH for your platform")
        dsc_lines.append("!endif")
        dsc_lines.append("")

    # generate the components to include in the DSC
    for flavor in flavors:
        for phase in phases:
            upper_phase = phase.upper()

            dsc_lines.append(
                f"!if $({upper_phase}_CRYPTO_SERVICES) == {flavor}")
            for arch in arches:
                if arch in ["ARM","IA32"] and phase == "StandaloneMm":
                    continue
                if arch in ["ARM","AARCH64"] and phase == "Smm":
                    continue
                comp_str = f"Components.{arch}"
                dsc_lines.append(
                    f" !if $({upper_phase}_CRYPTO_ARCH) == {arch}")
                dsc_lines.append(f"  [{comp_str}]")
                dsc_lines.append(
                    f"    CryptoPkg/Driver/Bin/{inf_start}_{flavor}_{phase}_$(TARGET)_{arch}.inf ")
                dsc_lines.append(" !endif")
            dsc_lines.append("")
            # Add the library as well
            comp_str = "Components"
            dsc_lines.append(f" [{comp_str}]")
            dsc_lines.append(
                f"   CryptoPkg/Library/BaseCryptLibOnProtocolPpi/{phase}CryptLib.inf " + "{")
            dsc_lines.append("     <PcdsFixedAtBuild>")
            dsc_lines.append(
                f"      !include CryptoPkg/Driver/Bin/Crypto.pcd.{flavor}.inc.dsc")
            dsc_lines.append("    }")
            dsc_lines.append("!endif\n")
    dsc_lines.append("")
    # generate the library classes to include
    dsc_lines.append("# LibraryClasses for ")
    for phase in phases:
        comp_types = get_supported_library_types(phase)
        upper_phase = phase.upper()
        for arch in arches:
            if arch in ["ARM","IA32"] and phase == "StandaloneMm":
                continue
            if arch in ["ARM","AARCH64"] and phase == "Smm":
                continue
            dsc_lines.append(f"!if $({upper_phase}_CRYPTO_ARCH) == {arch}")
            lib_class_str = ", ".join(map(lambda x: ".".join(
                ["LibraryClasses", arch, x.upper()]), comp_types))
            dsc_lines.append(f"  [{lib_class_str}]")
            dsc_lines.append(
                f"    BaseCryptLib|CryptoPkg/Library/BaseCryptLibOnProtocolPpi/{phase}CryptLib.inf")
            dsc_lines.append(
                f"    TlsLib|CryptoPkg/Library/BaseCryptLibOnProtocolPpi/{phase}CryptLib.inf")
            dsc_lines.append("!endif\n")

    generate_file_replacement(
        dsc_lines, None, "CryptoDriver.inc.dsc", options(), comment="#")

    for phase in phases:
        upper_phase = phase.upper()
        # now we generate the FDF includes
        fdf_bb_lines = []
        fdf_bb_lines.append(
            f"# include this in the platform {upper_phase} FV")
        fdf_bb_lines.append(f"!ifndef {upper_phase}_CRYPTO_SERVICES")
        fdf_bb_lines.append(f"!error You need to define {upper_phase}_CRYPTO_SERVICES")
        fdf_bb_lines.append("!endif")
        for flavor in flavors:
            fdf_bb_lines.append(f"!if $({upper_phase}_CRYPTO_SERVICES) == {flavor}")
            for target in targets:
                fdf_bb_lines.append(f" !if $(TARGET) == {target}")
                fdf_bb_lines.append(
                    f"    INF  CryptoPkg/Driver/Bin/{inf_start}_{flavor}_{phase}_{target}_$({upper_phase}_CRYPTO_ARCH).inf")
                fdf_bb_lines.append("  !endif")
            fdf_bb_lines.append("!endif\n")
        generate_file_replacement(
            fdf_bb_lines, None, f"CryptoDriver.{upper_phase}.inc.fdf", options(), comment="#")

def delete_files_of_pattern(pattern):
    files = glob.iglob(os.path.join(SCRIPT_DIR, pattern))
    for file_path in files:
        os.remove(file_path)


def get_supported_library_types(phase):
    phase = phase.upper()
    if phase == "PEI":
        return ["PEIM", "PEI_CORE"]
    elif phase == "DXE":
        return ["DXE_DRIVER", "UEFI_DRIVER", "UEFI_APPLICATION", "DXE_CORE"]
    elif phase == "SMM":
        return ["DXE_SMM_DRIVER", "SMM_CORE"]
    elif phase == "STANDALONEMM":
        return ["MM_STANDALONE", "MM_CORE_STANDALONE"]
    return ["", ]


if __name__ == "__main__":
    main()

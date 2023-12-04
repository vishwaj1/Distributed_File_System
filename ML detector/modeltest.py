import importlib
import pefile
import os
import array
import math
import pickle
import joblib
import sys
import argparse

def get_entropy(data):
    if not data:
        return 0.0
    
    occurences = array.array('L', [0] * 256)
    
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)

    return entropy

def get_resources(pe):
    """Extract resources :
    [entropy, size]"""
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)

                                resources.append([entropy, size])
        except Exception as e:
            return resources
    return resources

def get_version_info(pe):
    """Return version infos"""
    version_info = {}

    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            version_info.update(parse_string_file_info(fileinfo.StringTable))
        elif fileinfo.Key == 'VarFileInfo':
            version_info.update(parse_var_file_info(fileinfo.Var))

    if hasattr(pe, 'VS_FIXEDFILEINFO'):
        version_info.update(parse_fixed_file_info(pe.VS_FIXEDFILEINFO))

    return version_info

def parse_string_file_info(string_table):
    """Parse StringFileInfo"""
    info = {}
    for st in string_table:
        info.update(st.entries.items())
    return info

def parse_var_file_info(var_info):
    """Parse VarFileInfo"""
    return {var.entry.items()[0][0]: var.entry.items()[0][1] for var in var_info}

def parse_fixed_file_info(fixed_info):
    """Parse VS_FIXEDFILEINFO"""
    return {
        'flags': fixed_info.FileFlags,
        'os': fixed_info.FileOS,
        'type': fixed_info.FileType,
        'file_version': fixed_info.FileVersionLS,
        'product_version': fixed_info.ProductVersionLS,
        'signature': fixed_info.Signature,
        'struct_version': fixed_info.StrucVersion
    }

def extract_infos(fpath):
    pe = pefile.PE(fpath)
    
    # General information
    general_info = {
        'Machine': pe.FILE_HEADER.Machine,
        'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
        'Characteristics': pe.FILE_HEADER.Characteristics,
        'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
        'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
        'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
        'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
        'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
        'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
    }
    
    try:
        general_info['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
    except AttributeError:
        general_info['BaseOfData'] = 0

    general_info.update({
        'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
        'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
        'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
        'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
        'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
        'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
        'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
        'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
        'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
        'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
        'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
        'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
        'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
        'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
        'SizeOfStackCommit': pe.OPTIONAL_HEADER.SizeOfStackCommit,
        'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
        'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
        'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
        'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,
    })

    # Sections
    sections_info = {
        'SectionsNb': len(pe.sections),
        'SectionsMeanEntropy': 0,
        'SectionsMinEntropy': 0,
        'SectionsMaxEntropy': 0,
        'SectionsMeanRawsize': 0,
        'SectionsMinRawsize': 0,
        'SectionsMaxRawsize': 0,
        'SectionsMeanVirtualsize': 0,
        'SectionsMinVirtualsize': 0,
        'SectionMaxVirtualsize': 0,
    }

    if len(pe.sections) > 0:
        entropy = list(map(lambda x: x.get_entropy(), pe.sections))
        sections_info.update({
            'SectionsMeanEntropy': sum(entropy) / float(len(entropy)),
            'SectionsMinEntropy': min(entropy),
            'SectionsMaxEntropy': max(entropy),
        })

        raw_sizes = list(map(lambda x: x.SizeOfRawData, pe.sections))
        sections_info.update({
            'SectionsMeanRawsize': sum(raw_sizes) / float(len(raw_sizes)),
            'SectionsMinRawsize': min(raw_sizes),
            'SectionsMaxRawsize': max(raw_sizes),
        })

        virtual_sizes = list(map(lambda x: x.Misc_VirtualSize, pe.sections))
        sections_info.update({
            'SectionsMeanVirtualsize': sum(virtual_sizes) / float(len(virtual_sizes)),
            'SectionsMinVirtualsize': min(virtual_sizes),
            'SectionMaxVirtualsize': max(virtual_sizes),
        })

    # Imports
    imports_info = {
        'ImportsNbDLL': 0,
        'ImportsNb': 0,
        'ImportsNbOrdinal': 0,
    }

    try:
        imports_info.update({
            'ImportsNbDLL': len(pe.DIRECTORY_ENTRY_IMPORT),
            'ImportsNb': len(list(sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], []))),
            'ImportsNbOrdinal': len(list(filter(lambda x: x.name is None, importlib))),
        })
    except AttributeError:
        pass

    # Exports
    exports_info = {'ExportNb': 0}
    try:
        exports_info['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        pass

    # Resources
    resources_info = {
        'ResourcesNb': 0,
        'ResourcesMeanEntropy': 0,
        'ResourcesMinEntropy': 0,
        'ResourcesMaxEntropy': 0,
        'ResourcesMeanSize': 0,
        'ResourcesMinSize': 0,
        'ResourcesMaxSize': 0,
   
    }

def check_file_legitimacy(file):
    model=joblib.load("classifier/classifier.pkl")
    features=pickle.loads(open(os.path.join('classifier/features.pkl'),'rb').read())
    data=extract_infos(file)
    if data!={}:
        pe_features=list(map(lambda x: data[x],features))
        res=model.predict([pe_features])[0]
    else:
        res=1
    return res
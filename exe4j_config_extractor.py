#!python3
import sys
import os
import argparse
import struct
import pefile
from tabulate import tabulate

# EXE4J configuration extractor
# This helps extracting more info about PE files created with EXE4J
# Especially useful when they are only used to launch other files and don't embed the JAR that they launch

# string values in config
configPatterns = { 
	'Short name of application' 			: b'\x65\x00\x00\x00',
	'Redirect stderr'						: b'\x66\x00\x00\x00',
	'Error log path' 						: b'\x67\x00\x00\x00', # ends with + if Append activated
	'Redirect stdout'						: b'\x68\x00\x00\x00', 
	'Output log path' 						: b'\x69\x00\x00\x00', # ends with = if Append activated
	'Executable type' 						: b'\x6B\x00\x00\x00', # 4 is service, 2 is console, 1 is GUI
	'Show splash screen' 					: b'\x6C\x00\x00\x00',
	'Main class' 							: b'\x7A\x00\x00\x00',
	'VM parameters' 						: b'\x7B\x00\x00\x00',
	'Arguments for main class' 				: b'\x7C\x00\x00\x00',
	'Allow VM passthrough parameters' 		: b'\x7D\x00\x00\x00',
	'JRE search sequence' 					: b'\x80\x00\x00\x00',
	'Change working dir to' 				: b'\x92\x00\x00\x00', # empty if not set
	'Preferred VM'			 				: b'\x98\x00\x00\x00', # Client Hotspot, Server Hotspot; Default VM if not set
	'Allow -console parameter' 				: b'\x9C\x00\x00\x00',
	'Show splash screen text' 				: b'\xA3\x00\x00\x00',
	'Allow single instance run' 			: b'\x15\x27\x00\x00',
	'Splash screen status X position' 		: b'\x7D\x27\x00\x00',
	'Splash screen status Y position' 		: b'\x7E\x27\x00\x00',
	'Splash screen status line' 			: b'\x7F\x27\x00\x00',
	'Splash screen version X position' 		: b'\x84\x27\x00\x00',
	'Splash screen version Y position' 		: b'\x85\x27\x00\x00',
	'Splash screen version line' 			: b'\x86\x27\x00\x00'
	#'Nr of version specific VM parameters'	: b'\xD8\x27\x00\x00'
}
	
executable_type = {
	'1' : 'GUI',
	'2' : 'Console',
	'4' : 'Service'
}

preferred_vm = {
	'server' : 'Server HotSpot VM',
	'client' : 'Client HotSpot VM',
	'' : 'Default VM'
}

class NoExe4JFile(Exception):
	"""Raised when file is not an EXE4j wrapped PE"""
	pass

def findOverlay(filename):
	pe = pefile.PE(filename)
	offset = pe.get_overlay_data_start_offset()
	return offset

def is64Bit(filepath):
	pe = pefile.PE(filepath)
	magic = hex(pe.OPTIONAL_HEADER.Magic)
	return magic == '0x20b'

def searchPattern(pattern, sample, start_offset):
	content = ""
	offset = -1
	with open(sample, 'rb') as f:
		f.seek(start_offset)
		content = f.read()
		offset = content.find(pattern)
	return offset
		
def extract(offset, length, sample):
	result = b''
	if length > 0:
		with open(sample, 'rb') as f:
			f.seek(offset)
			result = f.read(length)
	return result
	
# return byte array for found config entry
def extractConfigEntry(start_offset, pattern, exefile):	
	size_offset = start_offset + 4 + searchPattern(pattern, exefile, start_offset)
	sizeBytes = extract(size_offset, 4, exefile)
	size = int.from_bytes(sizeBytes, "little")
	entry_offset = size_offset + 4
	entry = extract(entry_offset, size, exefile)
	if len(entry) > 0:
		try: 
			entry = entry.decode('utf-8')
		except UnicodeDecodeError:
			print('cannot decode entry at', hex(entry_offset), 'for pattern', pattern)
			entry = '<error>'
	else:
		entry = ''
	return entry
	
def constructJavaSearchSequence(value):
	result_string = ''
	values = value.split(';')
	for v in values:
		if v == 'Y':
			result_string += 'Search Windows registry'
		elif v.startswith('E'):
			result_string += 'Environmental variable: ' + v[1:]
		elif v.startswith('R'):
			result_string += 'Directory: ' + v[1:]
		result_string += '; '
	if result_string.endswith('; '): result_string = result_string[:-2]
	return result_string
	
def offsetToEmbeddedZIP(exefile):
	return searchPattern(b'\x50\x4B\x03\x04', exefile, 0)

def offsetToEmbeddedJarManifest(exefile):
	return searchPattern(b'\x4D\x45\x54\x41\x2D\x49\x4E\x46\x2F\x4D\x41\x4E\x49\x46\x45\x53\x54\x2E\x4D\x46', exefile, 0)
	
def extractConfig(exefile):
	overlay = findOverlay(exefile)
	if overlay == None: raise NoExe4JFile
	
	# magic of exe4j config D5 13 E4 E8 00 00 00 00
	config_offset = searchPattern(b'\xD5\x13\xE4\xE8\x00\x00\x00\x00', exefile, overlay)
	if config_offset == -1: 
		# magic of install4j config D5 13 E4 E8 01 00 00 00
		config_offset = searchPattern(b'\xD5\x13\xE4\xE8\x01\x00\x00\x00', exefile, overlay)
		if config_offset == -1: 
			raise NoExe4JFile
		print("This is an install4j executable!")
	config_offset += overlay
	
	print('EXE4j configuration found at offset', hex(overlay + config_offset))
	manifest_offset = offsetToEmbeddedJarManifest(exefile)
	print('Embedded Jar manifest offset', hex(manifest_offset) if manifest_offset != -1 else 'not found')
	zip_offset = offsetToEmbeddedZIP(exefile)
	print('Embedded ZIP offset', hex(zip_offset) + ' (use 7zip to extract files!)' if zip_offset != -1 else 'not found')		
	print("")
	
	result_table = []
	
	for description, pattern in configPatterns.items():
		value = extractConfigEntry(config_offset, pattern, exefile)
		if description == 'Executable type':
			value = executable_type.get(value, value)
			
		elif description == 'Error log path' or description == 'Output log path':
			if value.endswith('+'):
				value = value[:-1]
				result_table.append([description + ' append', '1'])
			else:
				result_table.append([description + ' append', '0'])
				
		elif description == 'JRE search sequence':
			value = constructJavaSearchSequence(value)
			
		elif description == 'Preferred VM':
			value = preferred_vm.get(value, value)
		
		elif description == 'Show splash screen' and value == '1':
			value += ' (check PE resources RCDATA for splash image)'
		
		result_table.append([description, value])
		
	result_table.append(['Bitness', '64 bit' if is64Bit(exefile) else '32 bit'])
	return result_table

def extractAndPrintConfig(exefile):
	result_table = extractConfig(exefile)
	print(tabulate(result_table, headers=["Key","Value"]))

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='EXE4j configuration extractor by Karsten Hahn @ GDATA CyberDefense')
	parser.add_argument('path', help='Exe4j executable file')

	args = parser.parse_args()

	try:
		if os.path.isdir(args.path):
			folder = args.path
			for r, d, f in os.walk(folder):
				for sample in f:
					extractAndPrintConfig(folder + sample)
					print("")
		else:
			sample = args.path
			extractAndPrintConfig(sample)
	except pefile.PEFormatError:
		print('File is no PE file!')
	except NoExe4JFile:
		print('PE File is not an EXE4J file!')
	print('')
	print('All done')
	

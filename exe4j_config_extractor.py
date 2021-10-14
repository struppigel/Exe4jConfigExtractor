#!python3
import sys
import os
import argparse
import struct
import pefile
from tabulate import tabulate

# EXE4J configuration extractor
# This helps extracting more info about PE files created with EXE4J

def findOverlay(filename):
	pe = pefile.PE(filename)
	offset = pe.get_overlay_data_start_offset()
	return offset

def searchPattern(pattern, sample, start_offset):
	content = ""
	offset = -1
	with open(sample, 'rb') as f:
		f.seek(start_offset)
		content = f.read()
		offset = content.find(pattern)
	return offset
		
def extract(offset, length, sample):
	result = ""
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
	entry = extract(entry_offset, size, exefile).decode('utf-8')
	return entry
	
def extractConfig(exefile):
	overlay = findOverlay(exefile)
	
	configPatterns = { 
		'Short name of application' : b'\x65\x00\x00\x00',
		'Error log path' 			: b'\x67\x00\x00\x00',
		'Output log path' 			: b'\x69\x00\x00\x00',
		'Main class' 				: b'\x7A\x00\x00\x00',
		'VM parameters' 			: b'\x7B\x00\x00\x00',
		'Arguments for main class' 	: b'\x7C\x00\x00\x00'
	}
	
	# magic of exe4j config D5 13 E4 E8
	config_offset = overlay + searchPattern(b'\xD5\x13\xE4\xE8', exefile, overlay)	
	print("Configuration found at offset", hex(config_offset))
	print("")
	result_table = []
	for description, pattern in configPatterns.items():
		value = extractConfigEntry(config_offset, pattern, exefile)
		result_table.append([description, value])
		
	return result_table

def extractAndPrintConfig(exefile):
	result_table = extractConfig(exefile)
	print(tabulate(result_table, headers=["Key","Value"]))

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Extract exe4j configuration. Karsten Hahn @ GDATA CyberDefense')
	parser.add_argument('path', help='Exe4j executable file')

	args = parser.parse_args()
	if os.path.isdir(args.path):
		folder = args.path
		for r, d, f in os.walk(folder):
			for sample in f:
				extractAndPrintConfig(folder + sample)
				print("")
	else:
		sample = args.path
		extractAndPrintConfig(sample)
	print('All done')
	
#!/bin/env python3 

import base64
import base58
import base45
import re
import time
import sys, os

#TO DO
#-----------------------------------
#fix Binary erroring

def clear():
	if os.name == "nt":
		win = os.system("cls")

	else:
		lin = os.system("clear")

def new():
	print()

def menu():
	print("1. Encode")
	print("2. Decode")
	print("3. Exit")
	print("-------------------")

#--------------Encode--------------

def asciiToBinary(data):
	ascBin = "".join([format(ord(i), '08b') for i in data])
	print("Base 2 (Binary):", ascBin)

def asciiToOctal(data):
	octalString = ""

	for char in data:
		octalCode = oct(ord(char))
		octalString += octalCode + " "

	print(f"Base 8 (Octal):", octalString) 

def asciiToDecimal(data):
	charCodes = [ord(char) for char in data]
	decString = ' '.join(str(code) for code in charCodes)
	print(f"Base 10 (Decimal):", decString)


def asciiToHex(data):
	asciiHex = data.encode("utf-8").hex()
	print("Base 16 (Hexadecimal):", asciiHex)

def asciiToBase32(data):
    stringBytes = data.encode("ascii")
    b64Bytes = base64.b32encode(stringBytes)
    b64String = b64Bytes.decode("ascii")
    print(f"Base 32:", b64String)

def asciiToBase45(data):
    # encode ASCII string into bytes
    bytesStr = data.encode('ascii')

    # Convert bytes to Base45
    base45Str = base45.b45encode(bytesStr).decode('utf-8')
    print("Base 45:", base45Str)

def asciiToBase58(data):
    asciiBase58 = base58.b58encode(data).decode('utf-8')
    print("Base 58:", asciiBase58)

def asciiToBase64(data):
	stringBytes = data.encode("ascii")
	b64Bytes = base64.b64encode(stringBytes)
	b64String = b64Bytes.decode("ascii")
	print(f"Base 64:", b64String)

#--------------Decode--------------

def binaryToAscii(data):
	newData = int(data, 2)
	asci = newData.to_bytes((newData.bit_length() + 7) // 8, 'big').decode()
	print("Binary:", asci)

def octalToAscii(data):
	octToInt = [int(octNum, 8) for octNum in data.split()] #octal string to integers
	IntToAscii = ''.join([chr(octNum) for octNum in octToInt]) #convert integer to ASCII
	
	print("Base 8 (Octal):", IntToAscii)

def decimalToAscii(data):
	
	asciiPhrase = "".join([chr(int(decimal)) for decimal in data.split()])

	print("Base 10 (Decimal):", asciiPhrase)

def hexToAscii(data):
    #removes the indicator that the encryption is hex so the program can decode the hex
    if data.startswith("0x"):
        data = data[2:]

    hexAscii = bytes.fromhex(data).decode('utf-8')
    
    print("Base 16 (Hexadecimal):", hexAscii)

def base32ToAscii(data):
    baseBytes = base64.b32decode(data)
    ascString = baseBytes.decode("ascii")
    
    print("Base 32:", ascString)

def base45ToAscii(data):

    # string to Base45
    base45Str = base45.b45decode(data).decode('utf-8')
    
    print("Base 45:", base45Str)

def base58ToAscii(data):
    base58Ascii = base58.b58decode(data).decode('utf-8')
    
    print("Base 58:", base58Ascii)

def base64ToAscii(data):
	stringBytesDec = base64.b64decode(data)
	string = stringBytesDec.decode("ascii")
	
	print(f"Base 64:", string)

def encoder(data):
	print("--------------------------------------")
	new()
	asciiToBinary(data)
	new()
	asciiToOctal(data)
	new()
	asciiToDecimal(data)
	new()
	asciiToHex(data)
	new()
	asciiToBase32(data)
	new()
	asciiToBase45(data)
	new()
	asciiToBase58(data)
	new()
	asciiToBase64(data)
	

def decoder(data):
	
	
	try:
		hexToAscii(data)

	except:
		pass
	
	try:
		binaryToAscii(data)

	except:
		pass

	try:
		octalToAscii(data)

	except:
		pass

	try:
		decimalToAscii(data)

	except:
		pass

	try:
		base64ToAscii(data)

	except:
		pass

	try:
		base32ToAscii(data)

	except:
		pass

	try:
		base45ToAscii(data)
	
	except:
		pass

	try:
		base58ToAscii(data)

	except:
		pass

def main():
	while True:
		clear()
		menu()
		response = input("Please enter a number: ")
		time.sleep(.5)
		clear()

		try:
			#Input sanitization	
			if response.isdigit() == False:
				raise ValueError

			if response.isdigit() == True:
				response = int(response)

				#If Response out of bounds	
				if response > 3 or response < 1:
					clear()
					print("Please enter a valid number: ")
					new()
					menu()
					continue

			if response == 1:
				data = input("Please enter a string to encode: ")
				encoder(data)
				return

			if response == 2:
				data = input("Please enter a string to decode: ")
				decoder(data)
				return

			elif response == 3:
				sys.exit(0)
		
		except ValueError:
			clear()
			print("Number was not entered")
			menu()
			continue

		except KeyboardInterrupt:
			print("Exiting\n")
			sys.exit(1)

main()
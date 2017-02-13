import sys
import os
import re
import subprocess
import argparse
import os.path
import hashlib
import sqlite3

parser = argparse.ArgumentParser()
parser.add_argument("-k",help="Key files are files associated with a campaign or threat actor.",action="store_true")
parser.add_argument("-u",help="Unremarkable files have no previously identified campaign or actor association.",action="store_true")
parser.add_argument("-s",help="Single file mode.",action="store_true")
parser.add_argument("-d",help="Calculate MD5 blocks from all files in a directory.")
parser.add_argument("-r",help="Calculate MD5 blocks from all files recursivley.")
parser.add_argument("-infile", help="Input File for single file mode.", type=argparse.FileType('r'))
parser.add_argument("-bs", help="Specify the blocksize in Bytes 1KB=1024 1MB=1024000.", required=True, type=int)
parser.add_argument("-output",help="Ouput directory for calculated MD5s.", required=True)
args=parser.parse_args()

#Check if user defined directory exists or create it.
if not os.path.exists(args.output):
	os.makedirs(args.output)

###################################
#Global
chunk = args.bs
outputd = args.output
###################################
#Variables for readandhash function
#Define input file
infile = args.infile
#Define output path:
x=1
outfile = outputd+"/block_file.txt"
outfile2 = outputd+"/block_file%s" %x+".txt"
###################################
#Variables for readandhashdir function:
indir = args.d 
indirrec = args.r
#SQLite Definitions:


#Function for reading single file for X bytes and returns MD5 hash value. Writes values to text file.
#THIS FUNCTION IS COMPELTE AND WORKING. OUTPUTS A TEXT FILE and SQLITE DB.
def readandhash():
		head, tail = os.path.split((infile.name)) #Pull filename only
		hashcount = 1
		fopen = open(outfile, 'w')
		data1 = infile.read(chunk)
		hashme = hashlib.md5(data1)
		fopen.write(str(hashcount))
		fopen.write("\t"+str(hashme.hexdigest()))
		fopen.write("\t"+tail)
		fopen.write("\t"+campaign)
		fopen.write('\n')
		while len(data1) > 0:
				data1 = infile.read(chunk)
				hashme = hashlib.md5(data1)
				hashcount+=1
				fopen.write(str(hashcount))
				fopen.write("\t"+str(hashme.hexdigest()))
				fopen.write("\t"+tail)
				fopen.write("\t"+campaign)
				fopen.write('\n')
		fopen.close()
		writesqliteSingle()


def readandhashdir():
	y = 1
	outfile2 = outputd+"/block_file%s" %x+".txt"
	for root, dirs, files in os.walk(indir):
		files = [f for f in files if not f[0]== "."]
		for file in files:
				if indir == root:
					with open(os.path.join(root, file), 'r') as fopen2:
						hashcount = 1
						woutput2 = open(outfile2, 'w')
						data2 = fopen2.read(chunk)
						hashme2 = hashlib.md5(data2)
						woutput2.write(str(hashcount))
						woutput2.write("\t"+str(hashme2.hexdigest()))
						woutput2.write("\t"+file)
						woutput2.write("\t"+str(campaign))
						woutput2.write('\n')
						while len(data2) > 0:
							hashcount+=1
							hashme2 = hashlib.md5(data2)
							woutput2.write(str(hashcount))
							woutput2.write("\t")
							woutput2.write(str(hashme2.hexdigest()))
							woutput2.write("\t"+file)
							woutput2.write("\t"+campaign)
							woutput2.write('\n')
							data2 = fopen2.read(chunk)
							if len(data2) == 0:
								woutput2.close()
								writesqliteDirectory(outfile2)
								hashcount = 1
								y += 1
								outfile2 = outputd+"/block_file%s" %y+".txt"



def readandhashrec():
		y=1
		outfile3 = outputd+"/block_file%s"%y+".txt"
		for root, dirs, files, in os.walk(indirrec):
			files = [f for f in files if not f[0] == "."] #ignores system files starting with a .
			dirs[:] = [d for d in dirs if not d[0] == "."] #ignores system directories starting with a .
			for file in files:
				with open(os.path.join(root, file), 'r') as auto:
					if not root == outputd:
						hashcount = 1
						woutput3 = open(outfile3, "w")
						data3 = auto.read(chunk)
						hashme3 = hashlib.md5(data3)
						woutput3.write(str(hashcount))
						woutput3.write("\t")
						woutput3.write(str(hashme3.hexdigest()))
						woutput3.write("\t"+file)
						woutput3.write("\t"+campaign)
						woutput3.write('\n')
						while len(data3) > 0:
							data3 = auto.read(chunk)
							hashme3 = hashlib.md5(data3)
							woutput3.write(str(hashcount))
							woutput3.write("\t")
							woutput3.write(hashme3.hexdigest())
							woutput3.write("\t"+file)
							woutput3.write("\t"+campaign)
							woutput3.write("\n")
							if len(data3) == 0:
								woutput3.close()
								writesqliteRecursive(outfile3)
								hashcount = 1
								y += 1
								outfile3 = outputd+"/block_file%s"%y+".txt"


def writesqliteSingle():
	db1 = sqlite3.connect(outputd+"/blockhashdb.sqlite3")
	cursor = db1.cursor()
	cursor.execute('CREATE TABLE IF NOT EXISTS hashes (count INT, md5 TEXT, filename TEXT, campaign TEXT)')
	for x in open(outfile).readlines():
		col1 = x.split('\t')[0]
		col2 = x.split('\t')[1]
		col3 = x.split('\t')[2]
		col4 = x.split('\t')[3]
		cursor.execute("INSERT INTO hashes (count, md5, filename, campaign) VALUES (?,?,?,?)",
		(col1, col2, col3, col4))
		db1.commit()
#Function opens outfile and reads line by line. Col1 and so forth is the first item in seperated by a space.
#Data is inserted into the database db1 into the table hashes. 


def writesqliteDirectory(outfile2):
	db1 = sqlite3.connect(outputd+"/blockhashdb.sqlite3")
	cursor = db1.cursor()
	cursor.execute('CREATE TABLE IF NOT EXISTS hashes (count INT, md5 TEXT, filename TEXT, campaign TEXT)')
	for x in open(outfile2).readlines():
		col1 = x.split('\t')[0]
		col2 = x.split('\t')[1]
		col3 = x.split('\t')[2]
		col4 = x.split('\t')[3]
		cursor.execute("INSERT INTO hashes (count, md5, filename, campaign) VALUES (?,?,?,?)",
		(col1, col2, col3, col4))
		db1.commit()
#Function opens outfile and reads line by line. Col1 and so forth is the first item in seperated by a space.
#Data is inserted into the database db1 into the table hashes. 


def writesqliteRecursive(outfile3):
	db1 = sqlite3.connect(outputd+"/blockhashdb.sqlite3")
	cursor = db1.cursor()
	cursor.execute('CREATE TABLE IF NOT EXISTS hashes (count INT, md5 TEXT, filename TEXT, campaign TEXT)')
	for x in open(outfile3).readlines():
		col1 = x.split('\t')[0]
		col2 = x.split('\t')[1]
		col3 = x.split('\t')[2]
		col4 = x.split('\t')[3]
		cursor.execute("INSERT INTO hashes (count, md5, filename, campaign) VALUES (?,?,?,?)",
		(col1, col2, col3, col4))
		db1.commit()
#Function opens outfile and reads line by line. Col1 and so forth is the first item in seperated by a space.
#Data is inserted into the database db1 into the table hashes. 

	
if (args.k and args.s):
	campaign = raw_input("Enter the campaign associated with they Keyfile: (TBD if unknown)")
	readandhash()
	print ("Output file written to: %s" % outfile)
elif (args.k and args.d):
	campaign = raw_input("Enter the campaign associated with they Keyfile: (TBD if unknown)")
	print("A directory of key files will be block hashed")
	readandhashdir()
elif (args.k and args.r):
	campaign = raw_input("Enter the campaign associated with they Keyfile: (TBD if unknown)")
	print("A group of directories containing key files will be block hashed")
	readandhashrec()


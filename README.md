# blocky_hash

Hashes have their value, but for some cases they are too absolute. Block hashing is a concept where a file is broken into blocks and individual hashes are produced from those blocks. 

Blocky hash works by reading in a specified chunk of data and then performing an MD5 hash on that chunk. The application continues until the end of the file is reached. The blocks are saved in text file and sqlite format. 

The application has a few use cases. The main purpose is to identify different files that may share similar blocks of data.

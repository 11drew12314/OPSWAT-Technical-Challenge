OPSWAT Technical Challenge
--------------------------
This is a simple program to scan a file against the metadefender.opswat.com API.

ENVIRONMENT
--------------------
This program was written using Python interpreter 3.10 on a computer running Ubuntu 20.04 & has also been tested on Windows 10.

Ubuntu 20.04 and other versions of Debian Linux ship with Python 3 pre-installed.

Build Instructions
--------
The only necessary package to install is Python's 'requests'

Pip is a tool for installing Python packages. To install Pip on Ubuntu 20.04, run the following commands as root or sudo user in the terminal.

```
$ sudo apt update
$ sudo apt install python3-pip
```
When the installation is complete, the installation can be verified by running

```$ pip3 --version```

To install the 'requests' package, run the following command:

```$ pip3 install requests```

Execution
-------
To run the program, there are two mandatory flags: _-upload_file_ and _-k_

```python3 main.py -upload_file [FILE] -k [API Key]```

Optional flags:
there are two additional flags that are not required, but may be specified.

```-hash_alg [ALGORITHM]``` can be used to specify the hash type. If this parameter is omitted, the default hash is MD5. Valid selections are 
1. MD5
2. SHA1
3. SHA256


```-n ```  The flag '-n' can be utilized to preserve the file's name after uploading and scanning the file to metadefender.opswat.com API. 

An example using both optional flags: 

```python3 main.py -upload_file samplefile.txt -k [API Key] -hash_alg SHA256 -n```

Logic
------
The logic employed  closely mirrors the description in the technical challenge's description.

1. Calculate the hash of a given file (i.e., samplefile.txt).
2. Perform a hash lookup against metadefender.opswat.com and see if there are previously cached results for the file.
3. If results are found, skip to step 6.
4. If results are not found, upload the file and receive a "data_id". 
5. Repeatedly pull on the "data_id" to retrieve results
6. Display results in the format outlined in the description.
7. Error handling for results are caught using the exceptions outlined in the Python3 <i>requests</i> module. Including JSON Errors, HTTP Errors, Connection Errors, Type Errors, etc.


Known Bugs
-----------
Step 3: this step is currently commented out. When cached results are found, the program only prints the first two lines of output:

```
filename: samplefile.txt
overall_status: No threat detected
```
before exiting.  When printing the response as text, I do receive the appropriate results 

```
{'appinfo': False, 'scan_result_history_length': 2, 'sandbox': False, 'file_id': 'bzIyMDcwNWQxbWo2MHF0bmM', 'data_id': 'bzIyMDcwNWQxbWo2MHF0bmNUODIzbnhFTVFv', 'scan_results': {'scan_details': {}, 'scan_all_result_i': 254, 'start_time': '2022-07-05T23:30:19.854Z', 'total_time': 0, 'total_avs': 0, 'total_detected_avs': 0, 'progress_percentage': 0, 'scan_all_result_a': 'In queue'}, 'file_info': {'file_size': 3167, 'upload_timestamp': '2022-07-05T23:30:19.600Z', 'md5': '49DC48B271AB1D38B84D5D6DB8202907', 'sha1': 'B27E526C4CB6883865C58EBC944AB68E854D90DB', 'sha256': '0CB4C8F9A767BFF8D1B29098F3A01EADECFB23A17AC9EF8DF722086AC266D008', 'file_type_category': '', 'file_type_description': '', 'file_type_extension': '', 'display_name': 'samplefile.txt'}, 'share_file': 1, 'private_processing': 0, 'rest_version': '4', 'scan_with': 'mdaas', 'additional_info': [], 'votes': {'up': 0, 'down': 0}, 'stored': True}
```

However, when I call the function to display the results, I am met with the following KeyError.

```

print("overall_status: {status}".format(status=outcome['scan_results']['scan_all_result_a']))
KeyError: 'scan_results'
```
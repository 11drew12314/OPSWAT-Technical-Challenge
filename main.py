#  Author: Andrew Lindsay
#  Date: 2022-07-06
#  File name: main.py
#  Description: a simple program to scan a file against the metadefender.opswat.com API. See README.md for more details.
import argparse
import hashlib
import requests
import sys


def analyze_file(api_key, file, filename=None):
    """
    Scanning a file starts with uploading the file to MetaDefender Cloud to initiate the scan process. Although we
    are trying to keep scanning very fast, scanning with more than 30 engines might take from a few seconds to many
    minutes depending on file type, file size, and current traffic. Also, archives usually take longer when scanning
    all the files inside. Due to these variables, we are not able to guarantee scanning times.

    Free API users are sent to different queues with a lower priority, and MetaDefender Cloud customers' scan
    requests are prioritized.

    Scanning a file consists of the following steps:

    1. Initiate scan request by uploading a file
    2. Retrieve scan report using unique data_id returned from Scan File API


    :param api_key: The apikey identifies and authenticates the user
    :param file: Path to the data file
    :param filename: File name is mainly for the descriptive purpose. File name does not affect the analysis. However,
    it is recommended to provide this info in order for you to associate the result with the actual file from the UI.
    :return: analysis: response contains {data_id, status, in_queue, queue_priority} as a dictionary.
    """

    url = "https://api.metadefender.com/v4/file"
    headers = {
        "apikey": api_key,  # set apikey to input value
        "Content-Type": "application/octet-stream",
        "filename": filename,
        "archivepwd": "{archivepwd}",  # set archivepwd to archive_pwd (if provided)
        # "filepassword": "{filepassword}",
        "samplesharing": "1",
        "privateprocessing": "0",
        # "downloadfrom": "{downloadfrom}",
        #"rule": "multiscan",
        #"sandbox": "windows10",
        #"sandbox_timeout": "short",
        #"sandbox_browser": "os_default",
        # "callbackurl": "{callbackurl}",
        # "rescan_count": "1",
        # "rescan_interval": "1"
    }
    try:
        response = requests.post(url=url, headers=headers, data=file)
        analysis = response.json()
    except requests.exceptions.JSONDecodeError as err_JSON_decode:
        print("Could not decode the text into json. ", err_JSON_decode)
        sys.exit(0)
    except requests.exceptions.InvalidJSONError as err_invalidJSON:
        print("A JSON error occurred. ", err_invalidJSON)
        sys.exit(0)
    except requests.exceptions.HTTPError as err_HTTP:
        print("An HTTP error occurred. ", err_HTTP)
        sys.exit(0)
    except requests.exceptions.ProxyError as err_proxy:
        print("A proxy error occurred. ", err_proxy)
        sys.exit(0)
    except requests.exceptions.SSLError as err_SSL:
        print("An SSL error occurred. ", err_SSL)
        sys.exit(0)
    except requests.exceptions.ConnectTimeout as err_connect_timeout:
        print("The request timed out while trying to connect to the remote server. ", err_connect_timeout)
        sys.exit(0)
    except requests.exceptions.ConnectionError as err_connection:
        print("A Connection error occurred. ", err_connection)
        sys.exit(0)
    except requests.exceptions.ReadTimeout as err_read_timeout:
        print("The server did not send any data in the alloted amount of time. ", err_read_timeout)
        sys.exit(0)
    except requests.exceptions.Timeout as err_timeout:
        print("The request timed out. ", err_timeout)
        sys.exit(0)
    except requests.exceptions.URLRequired as err_URL_reqd:
        print("A valid URL is required to make a request. ", err_URL_reqd)
        sys.exit(0)
    except requests.exceptions.TooManyRedirects as err_too_many:
        print("Too many redirects. ", err_too_many)
        sys.exit(0)
    except requests.exceptions.MissingSchema as err_missing_sch:
        print("The URL scheme (e.g. http or https) is missing. ", err_missing_sch)
        sys.exit(0)
    except requests.exceptions.InvalidSchema as err_invalid_sch:
        print("The URL scheme provided is either invalid or unsupported. ", err_invalid_sch)
        sys.exit(0)
    except requests.exceptions.InvalidProxyURL as err_invalid_proxy_URL:
        print("The proxy URL provided is invalid. ", err_invalid_proxy_URL)
        sys.exit(0)
    except requests.exceptions.InvalidURL as err_invalid_URL:
        print("The URL provided was somehow invalid. ", err_invalid_URL)
        sys.exit(0)
    except requests.exceptions.InvalidHeader as err_invalid_header:
        print("The header value provided was somehow invalid. ", err_invalid_header)
        sys.exit(0)
    except requests.exceptions.ChunkedEncodingError as err_chunked_enc:
        print("The server declared chunked encoding but sent an invalid chunk.", err_chunked_enc)
        sys.exit(0)
    except requests.exceptions.ContentDecodingError as err_content_dec:
        print("Failed to decode response content. ", err_content_dec)
        sys.exit(0)
    except requests.exceptions.StreamConsumedError as err_stream_consumed:
        print("The content for this response was already consumed. ", err_stream_consumed)
        sys.exit(0)
    except requests.exceptions.RetryError as err_retry:
        print("Custom retries logic failed. ", err_retry)
        sys.exit(0)
    except requests.exceptions.UnrewindableBodyError as err_unrewind_body:
        print("Requests encountered an error when trying to rewind a body. ", err_unrewind_body)
        sys.exit(0)
    except requests.exceptions.RequestException as err_req:
        print("There was an ambiguous exception that occurred while handling your request. ", err_req)
        sys.exit(0)
    except requests.exceptions.RequestsWarning as warning_req:
        print("Base warning for Requests. ", warning_req)
    except:
        print("Error, scan failed.")
        sys.exit(0)
    return analysis['data_id']


def fetch_analysis_result(url, api_key, metadata="0"):
    """
    Retrieve scan results.  Scan is done asynchronously and each scan request is tracked by a dataID. Initiating file
    scans and retrieving the results need to be done using two separate API calls. This request needs to be made
    multiple times until the scan is complete. Scan completion can be traced using scan_results.progress_percentage
    value from the response.
    :param url: https://api.metadefender.com/v4/file/{dataId}
    :param api_key: The apikey identifies and authenticates the user
    :param metadata: Retrieves file metadata and hash_results
    :return: fetched_data: response contains the file's scan_result_history
    """
    headers = {
        "apikey": api_key,
        "x-file-metadata": metadata
    }
    try:
        response = requests.get(url, headers=headers)
        fetched_data = response.json()
    except requests.exceptions.JSONDecodeError as err_JSON_decode:
        print("Could not decode the text into json. ", err_JSON_decode)
        sys.exit(0)
    except requests.exceptions.InvalidJSONError as err_invalidJSON:
        print("A JSON error occurred. ", err_invalidJSON)
        sys.exit(0)
    except requests.exceptions.HTTPError as err_HTTP:
        print("An HTTP error occurred. ", err_HTTP)
        sys.exit(0)
    except requests.exceptions.ProxyError as err_proxy:
        print("A proxy error occurred. ", err_proxy)
        sys.exit(0)
    except requests.exceptions.SSLError as err_SSL:
        print("An SSL error occurred. ", err_SSL)
        sys.exit(0)
    except requests.exceptions.ConnectTimeout as err_connect_timeout:
        print("The request timed out while trying to connect to the remote server. ", err_connect_timeout)
        sys.exit(0)
    except requests.exceptions.ConnectionError as err_connection:
        print("A Connection error occurred. ", err_connection)
        sys.exit(0)
    except requests.exceptions.ReadTimeout as err_read_timeout:
        print("The server did not send any data in the alloted amount of time. ", err_read_timeout)
        sys.exit(0)
    except requests.exceptions.Timeout as err_timeout:
        print("The request timed out. ", err_timeout)
        sys.exit(0)
    except requests.exceptions.URLRequired as err_URL_reqd:
        print("A valid URL is required to make a request. ", err_URL_reqd)
        sys.exit(0)
    except requests.exceptions.TooManyRedirects as err_too_many:
        print("Too many redirects. ", err_too_many)
        sys.exit(0)
    except requests.exceptions.MissingSchema as err_missing_sch:
        print("The URL scheme (e.g. http or https) is missing. ", err_missing_sch)
        sys.exit(0)
    except requests.exceptions.InvalidSchema as err_invalid_sch:
        print("The URL scheme provided is either invalid or unsupported. ", err_invalid_sch)
        sys.exit(0)
    except requests.exceptions.InvalidProxyURL as err_invalid_proxy_URL:
        print("The proxy URL provided is invalid. ", err_invalid_proxy_URL)
        sys.exit(0)
    except requests.exceptions.InvalidURL as err_invalid_URL:
        print("The URL provided was somehow invalid. ", err_invalid_URL)
        sys.exit(0)
    except requests.exceptions.InvalidHeader as err_invalid_header:
        print("The header value provided was somehow invalid. ", err_invalid_header)
        sys.exit(0)
    except requests.exceptions.ChunkedEncodingError as err_chunked_enc:
        print("The server declared chunked encoding but sent an invalid chunk.", err_chunked_enc)
        sys.exit(0)
    except requests.exceptions.ContentDecodingError as err_content_dec:
        print("Failed to decode response content. ", err_content_dec)
        sys.exit(0)
    except requests.exceptions.StreamConsumedError as err_stream_consumed:
        print("The content for this response was already consumed. ", err_stream_consumed)
        sys.exit(0)
    except requests.exceptions.RetryError as err_retry:
        print("Custom retries logic failed. ", err_retry)
        sys.exit(0)
    except requests.exceptions.UnrewindableBodyError as err_unrewind_body:
        print("Requests encountered an error when trying to rewind a body. ", err_unrewind_body)
        sys.exit(0)
    except requests.exceptions.RequestException as err_req:
        print("There was an ambiguous exception that occurred while handling your request. ", err_req)
        sys.exit(0)
    except requests.exceptions.RequestsWarning as warning_req:
        print("Base warning for Requests. ", warning_req)
    except:
        print("Error, scan failed {0}")
        sys.exit(0)

    return fetched_data


def calculate_hash(type_of_hash, file_to_hash, buffer_size=65536):
    """
    (Logic; Step 1). Calculate the hash of a given file
    :param type_of_hash: Specify which hash algorithm to use (MD5, SHA-1, SHA-256) [String]
    :param file_to_hash: Specify the name of the file to hash [String]
    :param buffer_size: Specify the chunk size to use. Default parameter is set to 65536 (2^16) bytes.
                       This is considered to be the best chunk/buffer size for MD5
    :return: the hashed input file as a hexdigest (string of double length, containing only hexadecimal digits)
    """
    type_of_hash = type_of_hash.lower()
    try:
        if type_of_hash == "sha1":
            hash_obj = hashlib.sha1()
        elif type_of_hash == "sha256":
            hash_obj = hashlib.sha256()
        else:
            hash_obj = hashlib.md5()
        with open(file_to_hash, 'rb') as f:
            for chunk in iter(lambda: f.read(buffer_size), b''):
                hash_obj.update(chunk)
    except:
        print("Error: hashing of file ", file_to_hash, " failed. Exiting.")
        sys.exit(0)
    return hash_obj.hexdigest()


def display_results(outcome):
    """
    (Logic; Step 6). Display results in the specified format
    :param outcome: necessary to determine various output threads
    """
    print("filename: {file_name}".format(file_name=args.save))
    print("overall_status: {status}".format(status=outcome['scan_results']['scan_all_result_a']))

    for i, j in outcome['scan_results']['scan_details'].items():
        print("\n\nengine: {engine}".format(engine=i))
        print("\nthread_found: {thread}".format(thread=j['threat_found'] if j['threat_found'] else 'clean'))
        print("\nscan_result: {result}".format(result=j['scan_result_i']))
        print("\ndef_time: {time}".format(time=j['def_time']))


def parse_arguments():
    parser = argparse.ArgumentParser()

    # Required Arguments
    parser.add_argument("-upload_file", "--upload_file", dest="file", required=True,
                        help="Enter the name of desired file to scan.")

    parser.add_argument("-k", "--key", dest="key", required=True,
                        help="Enter a valid OPSWAT API key to access the MetaDefender Cloud service.")
    # Optional Arguments
    parser.add_argument("-hash_alg", "--hash_alg", dest="hash", required=False, default="md5",
                        help="(Optional) Select a hashing algorithm [MD5, SHA1, SHA256]. Default algorithm is MD5. ")

    parser.add_argument("-n", "--name", dest="save", action="store_true", required=False, default=None,
                        help="(Optional) Elect to retain the file name after scan/upload.")

    arguments = parser.parse_args()

    if arguments.save:
        arguments.save = arguments.file

    return arguments


if __name__ == '__main__':
    args = parse_arguments()

    # 1. Calculate hash of a given file (i.e., samplefile.txt).
    file_hash = calculate_hash(args.hash, args.file).upper()

    # 2. Perform a hash lookup against metadefender.opswat.com and see if there are previously cached results for the
    #    file.
    url = "https://api.metadefender.com/v4/hash/{0}".format(file_hash)
    cached_result = fetch_analysis_result(url=url, api_key=args.key)
    headers = {
        "apikey": args.key
    }
    response = requests.request("GET", url, headers=headers)

    # 3. If [cached] results are found, skip to step 6.
    #if "404003" not in response.text:  # error code 404003 {"error":{"code":404003,"messages":["The hash was not found"]}}
    #    display_results(cached_result)
    #    sys.exit(0)

    # 4. If [cached] results are not found, upload the file and receive a "data_id"
    with open(args.file, 'rb') as file_to_upload:
        payload = file_to_upload.read()
    data_id = analyze_file(api_key=args.key, file=payload, filename=args.save)

    # 5. Repeatedly pull on the "data_id" to retrieve results.
    url = "https://api.metadefender.com/v4/file/{0}".format(data_id)
    retrieved_result = fetch_analysis_result(url=url, api_key=args.key)
    while retrieved_result['scan_results']['progress_percentage'] != 100:
        retrieved_result = fetch_analysis_result(url=url, api_key=args.key)

    # 6. Display results in the specified format
    display_results(retrieved_result)
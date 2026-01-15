import csv
import json
import base64
import sys
import os
from datetime import datetime
from urllib.parse import urlparse, parse_qs

# ===============================================
# 1. Increase field size limit (for large files)
# ===============================================
try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(2147483647)

def decode_base64_safe(data):
    """Base64 decoding safely"""
    if not data or not isinstance(data, str):
        return ""
    try:
        decoded = base64.b64decode(data)
        return decoded.decode('utf-8', errors='replace')
    except Exception:
        return data

def parse_http_headers(raw_text):
    """Extracting my HTTP request/response headers"""
    headers = []
    if not raw_text or not isinstance(raw_text, str):
        return headers
    try:
        lines = raw_text.split('\r\n')
        for line in lines[1:]:
            if not line.strip():
                break
            if ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    headers.append({
                        "name": parts[0].strip(), 
                        "value": parts[1].strip()
                    })
    except Exception:
        pass
    return headers

def parse_cookies_from_headers(headers):
    """Extracting cookies from headers"""
    cookies = []
    for header in headers:
        if header.get('name', '').lower() in ['cookie', 'set-cookie']:
            cookie_str = header.get('value', '')
            # Simple analysis of cookies
            for cookie_part in cookie_str.split(';'):
                if '=' in cookie_part:
                    name, value = cookie_part.split('=', 1)
                    cookies.append({
                        "name": name.strip(),
                        "value": value.strip()
                    })
    return cookies

def extract_http_version(raw_text):
    """Extract the HTTP version"""
    if not raw_text or not isinstance(raw_text, str): 
        return "HTTP/1.1"
    try:
        first = raw_text.split('\r\n')[0] if '\r\n' in raw_text else raw_text.split('\n')[0]
        if 'HTTP/2' in first: 
            return 'HTTP/2'
        elif 'HTTP/1.0' in first: 
            return 'HTTP/1.0'
        elif 'HTTP/1.1' in first:
            return 'HTTP/1.1'
    except: 
        pass
    return 'HTTP/1.1'

def extract_status_text(raw_response):
    """Extract response status text (eg OK, Not Found)"""
    if not raw_response or not isinstance(raw_response, str): 
        return ""
    try:
        first = raw_response.split('\r\n')[0] if '\r\n' in raw_response else raw_response.split('\n')[0]
        parts = first.split(' ', 2)
        if len(parts) >= 3: 
            return parts[2].strip()
    except: 
        pass
    return ""

def extract_body(raw_text):
    """Extract the body of the request or response"""
    if not raw_text or not isinstance(raw_text, str): 
        return ""
    try:
        if '\r\n\r\n' in raw_text: 
            return raw_text.split('\r\n\r\n', 1)[1]
        elif '\n\n' in raw_text: 
            return raw_text.split('\n\n', 1)[1]
    except: 
        pass
    return ""

def extract_query_string(url):
    """Extracting query parameters from the URL"""
    if not url:
        return []
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        query_list = []
        for key, values in params.items():
            for value in values:
                query_list.append({"name": key, "value": value})
        return query_list
    except:
        return []

def calculate_headers_size(headers):
    """Approximate header size calculation"""
    if not headers:
        return -1
    try:
        total = 0
        for h in headers:
            total += len(h.get('name', '')) + len(h.get('value', '')) + 4  # name: value\r\n
        return total
    except:
        return -1

def safe_int(value, default=0):
    """Safe conversion to integer"""
    if value is None or value == '': 
        return default
    try:
        clean = str(value).strip().replace(',', '')
        if clean.replace('-', '').replace('.', '').isdigit(): 
            return int(float(clean))
    except: 
        pass
    return default

def safe_float(value, default=0.0):
    """Safe conversion to float"""
    if value is None or value == '': 
        return default
    try:
        clean = str(value).strip().replace(',', '')
        return float(clean)
    except: 
        pass
    return default

def calculate_timings(row):
    """Calculate timings accurately from available data"""
    start = safe_float(row.get('Start response timer'))
    end = safe_float(row.get('End response timer'))
    
    wait_time = max(0, end - start) if (start and end) else 0
    
    # Try to extract additional timings if they exist
    send = safe_float(row.get('Send time'), 0)
    receive = safe_float(row.get('Receive time'), 0)
    
    return {
        "blocked": -1,
        "dns": -1,
        "connect": -1,
        "send": send,
        "wait": wait_time,
        "receive": receive,
        "ssl": -1
    }

def get_mime_type_from_headers(headers):
    """Extract MIME type from Content-Type header"""
    for header in headers:
        if header.get('name', '').lower() == 'content-type':
            value = header.get('value', '')
            # Extract the first part before;
            return value.split(';')[0].strip()
    return ""

def convert_csv_to_har_stream(csv_file_path, output_har_path, preserve_all_data=True):
    """
Convert huge CSV to HAR while saving all data without exception.
    
    Args:
        csv_file_path: CSV file path
        output_har_path: Path of the output HAR file
        preserve_all_data: Save all original columns in a custom field    
        """
    
    if not os.path.exists(csv_file_path):
        print(f" File not found: {csv_file_path}")
        return False
    
    processed_count = 0
    error_count = 0
    
    try:
        with open(csv_file_path, 'r', encoding='utf-8', errors='replace') as f_in, \
             open(output_har_path, 'w', encoding='utf-8') as f_out:
            
            reader = csv.DictReader(f_in)
            
            # Print the column names to check
            if reader.fieldnames:
                print(f"📋 Available columns: {', '.join(reader.fieldnames)}")
            
            # Write the beginning of the HAR file
            f_out.write('{\n  "log": {\n')
            f_out.write('    "version": "1.2",\n')
            f_out.write('    "creator": {\n')
            f_out.write('      "name": "Complete CSV to HAR Converter",\n')
            f_out.write('      "version": "4.0",\n')
            f_out.write('      "comment": "Preserves all original CSV data"\n')
            f_out.write('    },\n')
            f_out.write('    "entries": [\n')
            
            first_entry = True
            
            print("🚀 Start processing(Streaming Mode)...")
            print("=" * 60)
            
            for idx, row in enumerate(reader, 1):
                try:
                    # Decryption if present
                    raw_req = decode_base64_safe(row.get('Request', ''))
                    raw_res = decode_base64_safe(row.get('Response', ''))
                    
                    # Extract Headers
                    req_headers = parse_http_headers(raw_req)
                    res_headers = parse_http_headers(raw_res)
                    
                    # Extract Cookies
                    req_cookies = parse_cookies_from_headers(req_headers)
                    res_cookies = parse_cookies_from_headers(res_headers)
                    
                    # Extract Bodies
                    req_body = extract_body(raw_req)
                    res_body = extract_body(raw_res)
                    
                    # Extract MIME type from headers or CSV
                    response_mime = get_mime_type_from_headers(res_headers) or row.get('MIME type', '').strip()
                    
                    # Built Request
                    method = row.get('Method', 'GET').strip() or 'GET'
                    url = row.get('URL', '').strip()
                    
                    request_obj = {
                        "method": method,
                        "url": url,
                        "httpVersion": extract_http_version(raw_req),
                        "cookies": req_cookies,
                        "headers": req_headers,
                        "queryString": extract_query_string(url),
                        "headersSize": calculate_headers_size(req_headers),
                        "bodySize": len(req_body.encode('utf-8')) if req_body else 0
                    }
                    
                    # Add postData if it exists
                    if req_body and method.upper() in ["POST", "PUT", "PATCH", "DELETE"]:
                        request_mime = get_mime_type_from_headers(req_headers) or "application/octet-stream"
                        request_obj["postData"] = {
                            "mimeType": request_mime,
                            "text": req_body,
                            "params": []
                        }
                    
                    # Build Response
                    status_code = safe_int(row.get('Status code'))
                    content_size = safe_int(row.get('Length'), -1)
                    
                    response_obj = {
                        "status": status_code,
                        "statusText": extract_status_text(raw_res),
                        "httpVersion": extract_http_version(raw_res) if raw_res else extract_http_version(raw_req),
                        "cookies": res_cookies,
                        "headers": res_headers,
                        "content": {
                            "size": content_size,
                            "mimeType": response_mime,
                            "text": res_body,
                            "encoding": "utf-8"
                        },
                        "redirectURL": row.get('Redirect URL', '').strip(),
                        "headersSize": calculate_headers_size(res_headers),
                        "bodySize": content_size
                    }
                    
                    # Calculate time
                    timings = calculate_timings(row)
                    total_time = sum(v for v in timings.values() if v > 0)
                    
                    # Build Entry
                    entry = {
                        "startedDateTime": row.get('Time', datetime.now().isoformat()),
                        "time": total_time,
                        "request": request_obj,
                        "response": response_obj,
                        "cache": {},
                        "timings": timings,
                        "serverIPAddress": row.get('IP', '').strip(),
                        "connection": row.get('Connection ID', '').strip()
                    }
                    
                    # Save all original data (very important!)
                    if preserve_all_data:
                        entry["_csvOriginalData"] = {k: v for k, v in row.items()}
                    
                    # Write the item
                    if not first_entry:
                        f_out.write(',\n')
                    
                    f_out.write('      ')
                    json.dump(entry, f_out, ensure_ascii=False, indent=2)
                    
                    first_entry = False
                    processed_count += 1
                    
                    # Progress report
                    if idx % 500 == 0:
                        print(f"⏳ proccess: {idx:,} ...", end='\r')
                
                except Exception as e:
                    error_count += 1
                    if error_count <= 5:  # Print only the first 5 errors
                        print(f"\n⚠️ Row error {idx}: {str(e)[:100]}")
                    continue
            
            # Close the HAR file
            f_out.write('\n    ]\n  }\n}')
            
            # The report is final
            print("\n" + "=" * 60)
            print(f"✅ Conversion completed successfully!")
            print(f"📊 Total records processed: {processed_count:,}")
            if error_count > 0:
                print(f"⚠️ Number of errors (skipped): {error_count:,}")
            print(f"📁 Output file: {output_har_path}")
            
            # File size
            file_size = os.path.getsize(output_har_path)
            if file_size > 1024*1024*1024:
                print(f"💾 File size: {file_size/(1024*1024*1024):.2f} GB")
            elif file_size > 1024*1024:
                print(f"💾 File size: {file_size/(1024*1024):.2f} MB")
            else:
                print(f"💾 File size: {file_size/1024:.2f} KB")
            
            return True

    except Exception as e:
        print(f"\n❌ Serious error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("🔄 CSV to HAR Converter - Complete Edition")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        print("\n📖 Usage:")
        print("  python script.py <input.csv> [output.har]")
        print("\nExample:")
        print("  python script.py data.csv result.har")
        sys.exit(1)
    
    input_csv = sys.argv[1]
    output_har = sys.argv[2] if len(sys.argv) >= 3 else f"{os.path.splitext(input_csv)[0]}_complete.har"
    
    success = convert_csv_to_har_stream(input_csv, output_har, preserve_all_data=True)
    
    if success:
        print("\n✨ Done! You can now open the file in any HAR Viewer")
    else:
        print("\n❌ Conversion failed. See errors above.")
        sys.exit(1)

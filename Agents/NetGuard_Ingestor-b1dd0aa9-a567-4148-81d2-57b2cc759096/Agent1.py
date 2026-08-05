import boto3
import os
import pandas as pd
from io import StringIO
from datetime import datetime
import uuid
from zoneinfo import ZoneInfo
import math  
from pandas.errors import EmptyDataError  
 
print("NetGuard Ingestor started successfully.")
 
# Create an S3 client
s3 = boto3.client('s3')
 
# Retrieve environment variables
NETWORK_TRAFFIC_BUCKET = os.environ['NETWORK_TRAFFIC_BUCKET']
# CHUNKS_BUCKET will hold the smaller chunk files; if not set, default to NETWORK_TRAFFIC_BUCKET
CHUNKS_BUCKET = os.environ.get('CHUNKS_BUCKET', NETWORK_TRAFFIC_BUCKET)
 
def read_input_data(bucket, key):
    """
    Reads an input file from S3.
    Supports CSV and JSON file formats.
    Raises ValueError if file is unsupported or empty.
    """
    print(f"[DEBUG] Reading file from: s3://{bucket}/{key}")
    obj = s3.get_object(Bucket=bucket, Key=key)
    content = obj['Body'].read().decode('utf-8')
   
    # Print a preview of the file content (first 200 characters)
    preview_len = min(len(content), 200)
    print(f"[DEBUG] File content preview ({preview_len} chars): {content[:preview_len]}")
 
    # Check if the file is empty (ignoring whitespace)
    if not content.strip():
        raise ValueError("[DEBUG] The file is empty. No processing done.")
 
    # Handle supported formats (CSV, JSON), else raise ValueError
    if key.lower().endswith('.csv'):
        print("[DEBUG] Detected CSV format. Parsing with pd.read_csv().")
        try:
            return pd.read_csv(StringIO(content))
        except EmptyDataError:
            raise ValueError("[DEBUG] The file is empty (EmptyDataError). No processing done.")
    elif key.lower().endswith('.json'):
        print("[DEBUG] Detected JSON format. Parsing with pd.read_json().")
        return pd.read_json(StringIO(content))
    else:
        raise ValueError("[DEBUG] Unsupported file format. Only CSV and JSON are supported.")
 
def lambda_handler(event, context):
    """
    Lambda handler for NetGuard Ingestor.
    Triggered by an S3 event whenever a new file is uploaded to NETWORK_TRAFFIC_BUCKET.
    Reads the file, normalizes the data, checks for missing row-level values (logging a warning),
    then splits it into chunks using the new rules, and writes the chunks to CHUNKS_BUCKET.
    Returns a list of S3 keys for the generated chunk files, including a warning in the final message if missing data is found.
    """
    print("[DEBUG] Lambda handler invoked.")
    print(f"[DEBUG] Environment variable - NETWORK_TRAFFIC_BUCKET: {NETWORK_TRAFFIC_BUCKET}")
    print(f"[DEBUG] Environment variable - CHUNKS_BUCKET: {CHUNKS_BUCKET}")
   
    # Print the entire event for debugging
    print(f"[DEBUG] Event received: {event}")
   
    # Extract S3 event details
    record = event['Records'][0]
    s3_bucket = record['s3']['bucket']['name']
    s3_key = record['s3']['object']['key']
   
    print(f"[DEBUG] S3 bucket from event: {s3_bucket}")
    print(f"[DEBUG] S3 key from event: {s3_key}")
   
    # Only process files from the network traffic bucket
    if s3_bucket != NETWORK_TRAFFIC_BUCKET:
        print(f"[DEBUG] File {s3_key} is not from the expected bucket ({NETWORK_TRAFFIC_BUCKET}). Skipping.")
        return {'statusCode': 200, 'body': f"Skipped file from {s3_bucket}."}
   
    print(f"[DEBUG] Reading input file from bucket: {s3_bucket}, key: {s3_key}")
   
    # Wrap in try/except to handle ValueError from read_input_data
    try:
        df = read_input_data(s3_bucket, s3_key)
    except ValueError as e:
        error_message = str(e)
        print(f"[ERROR] {error_message}")
        if "unsupported file format" in error_message.lower():
            return {
                'statusCode': 400,
                'body': "[DEBUG] Unsupported file format. Only CSV and JSON are supported."
            }
        elif "empty" in error_message.lower():
            return {
                'statusCode': 200,
                'body': "Empty file provided; no processing done."
            }
        else:
            return {
                'statusCode': 400,
                'body': f"Error encountered: {error_message}"
            }
   
    # New Check: If the DataFrame is empty, return an empty file response.
    if df.empty:
        print("[DEBUG] DataFrame is empty after reading the file.")
        return {
            'statusCode': 200,
            'body': "Empty file provided; no processing done."
        }
   
    # Debug: print original DataFrame shape and columns
    print(f"[DEBUG] Original DataFrame shape: {df.shape}")
    print(f"[DEBUG] Original DataFrame columns: {list(df.columns)}")
   
    # Normalize column names: strip spaces and convert to lowercase
    df.columns = [col.strip().replace(" ", "").lower() for col in df.columns]
    print(f"[DEBUG] Normalized DataFrame columns: {list(df.columns)}")
   
    # New Check: Verify required columns exist
    required_columns = ['sourceip', 'destinationip']
    for col in required_columns:
        if col not in df.columns:
            print(f"[ERROR] Missing required column: {col}")
            return {
                'statusCode': 400,
                'body': f"Missing required column: {col}. Processing halted."
            }
   
    # Check for missing values in key columns, just to log and warn
    columns_to_check = [
        'sourceip', 'destinationip', 'sourceport',
        'destinationport', 'protocol', 'packetsize',
        'flags', 'connectionstatus'
    ]
   
    missing_details = []
    for col in columns_to_check:
        if col in df.columns:
            col_missing = df[col].isnull().sum()
            if col_missing > 0:
                # Collect info for final message
                missing_details.append(f"{col}:{col_missing}")
   
    # Print a single warning line if any missing values were found
    if missing_details:
        warning_text = "[WARNING] Missing values detected -> " + ", ".join(missing_details)
        print(warning_text)
    else:
        print("[DEBUG] No row-level missing values detected in key columns.")
   
    total_rows = len(df)
    print(f"[DEBUG] Total rows in input DataFrame: {total_rows}")
   
    # Updated chunking logic:
    if total_rows <= 100:
        desired_num_chunks = 1
        chunk_size = total_rows
        print(f"[DEBUG] Input has {total_rows} rows (<= 100). Creating 1 chunk with all rows.")
    elif total_rows < 1000:
        desired_num_chunks = 5
        chunk_size = math.ceil(total_rows / desired_num_chunks)
        print(f"[DEBUG] Input has {total_rows} rows (> 100 and < 1000). Creating {desired_num_chunks} chunks with approx {chunk_size} rows each.")
    else:
        chunk_size = 200
        desired_num_chunks = math.ceil(total_rows / chunk_size)
        print(f"[DEBUG] Input has {total_rows} rows (>= 1000). Creating chunks with exactly {chunk_size} rows each.")
        print(f"[DEBUG] Calculated total chunks needed: {desired_num_chunks}")
   
    chunk_keys = []  # List to store the S3 keys of generated chunks
   
    # Create an EST timestamp string
    est_zone = ZoneInfo("America/New_York")
    timestamp_est_str = datetime.now(est_zone).strftime("%Y-%m-%d_%H-%M-%S_%Z")
   
    # Initialize chunk index
    chunk_index = 0
   
    # Split the DataFrame into chunks using the computed chunk_size
    for i in range(0, total_rows, chunk_size):
        chunk_index += 1
        chunk_df = df.iloc[i:i+chunk_size]
        current_chunk_count = len(chunk_df)
        print(f"[DEBUG] Processing rows {i} to {i + current_chunk_count - 1} (Chunk #{chunk_index})")
       
        # Construct a filename using the EST timestamp and chunk index, storing chunks in the temporary folder "temp_chunks/"
        chunk_filename = f"chunks/network_traffic_{timestamp_est_str}_chunk{chunk_index}.csv"
        print(f"[DEBUG] Generated chunk filename: {chunk_filename}")
       
        # Convert the chunk to CSV and upload it to S3
        csv_buffer = StringIO()
        chunk_df.to_csv(csv_buffer, index=False)
        print(f"[DEBUG] Uploading chunk to: s3://{CHUNKS_BUCKET}/{chunk_filename}")
        s3.put_object(Bucket=CHUNKS_BUCKET, Key=chunk_filename, Body=csv_buffer.getvalue())
        print(f"[DEBUG] Successfully uploaded chunk: s3://{CHUNKS_BUCKET}/{chunk_filename}")
       
        chunk_keys.append(chunk_filename)
   
    print(f"[DEBUG] All chunk keys generated: {chunk_keys}")
   
    # Build final message
    final_message = f"Successfully processed {total_rows} rows into {chunk_index} chunks."
    if missing_details:
        # Append a short note about missing values
        final_message += " WARNING: Missing values found in dataset."
   
    return {
        'statusCode': 200,
        'chunk_keys': chunk_keys,
        'message': final_message
    }
 
 
 
 
 
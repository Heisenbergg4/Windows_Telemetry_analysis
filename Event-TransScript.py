import json
import os
import sqlalchemy as sql
import sqlalchemy.orm as sql_orm
import csv
import argparse
import magic

class EventTranscriptAnalyzer:
    def __init__(self, db_path, output_directory):
        self.db_path = db_path
        self.output_directory = output_directory
        self.engine = sql.create_engine(f'sqlite:///{db_path}')
        Session = sql_orm.sessionmaker(self.engine)
        self.session = Session()
        
    def analyze(self):
        """Run all analysis functions and return a summary of results"""
        results = {}
        
        print("\nAnalyzing EventTranscript.db...")
        results["Edge Browsing History"] = self.edge_browsing_history()
        results["Application Inventory"] = self.application_inventory()
        results["Application Execution"] = self.application_execution()
        results["User Defaults"] = self.user_defaults()
        results["WiFi Connected Events"] = self.wifi_connected_events()
        results["SRUM App Activity"] = self.srum_app_activity()
        results["WLAN Scan Results"] = self.wlan_scan_results()
        results["SRUM Network Usage"] = self.srum_network_usage()
        
        return results
        
    def edge_browsing_history(self):
        result = self.session.execute(sql.text('SELECT events_persisted.sid, events_persisted.payload from events_persisted inner join event_tags on events_persisted.full_event_name_hash = event_tags.full_event_name_hash inner join tag_descriptions on event_tags.tag_id = tag_descriptions.tag_id where (tag_descriptions.tag_id = "1" and events_persisted.full_event_name LIKE "%Aria.218d658af29e41b6bc37144bd03f018d.Microsoft.WebBrowser.HistoryJournal%")'))
        history_events = result.fetchall()

        if len(history_events) == 0:
            print("Microsoft Edge browsing history events not recorded in this database. Will not create CSV")
            return 0
        else:
            print(f"{len(history_events)} events related to browsing history from MS Edge found. Extracting & writing to CSV.")
            browsinghistory_csv = open(os.path.join(self.output_directory, "Edge Browsing History.csv"), "w", newline='')
            browsinghistory_csv_writer = csv.writer(browsinghistory_csv, dialect='excel')
            browsinghistory_csv_writer.writerow(["Visited URL", "Visit Timestamp (UTC)", "Refer URL", "SID"])

            count = 0
            for events in history_events:
                row_list = []
                temp_json = json.loads(events[1])

                if 'navigationUrl' in temp_json['data']:
                    row_list.append(temp_json['data']['navigationUrl'])
                    row_list.append(temp_json['data'].get('Timestamp', 'N/A').replace("T", " ").replace("Z", ""))

                    if 'referUrl' in temp_json['data']:
                        row_list.append(temp_json['data']['referUrl'])
                    else:
                        row_list.append("")
                    
                    row_list.append(events[0])
                    browsinghistory_csv_writer.writerow(row_list)
                    count += 1
            browsinghistory_csv.close()
            return count

    def application_inventory(self):
        result = self.session.execute(sql.text('SELECT events_persisted.sid, events_persisted.payload from events_persisted inner join event_tags on events_persisted.full_event_name_hash = event_tags.full_event_name_hash inner join tag_descriptions on event_tags.tag_id = tag_descriptions.tag_id where (tag_descriptions.tag_id = 31 and events_persisted.full_event_name="Microsoft.Windows.Inventory.Core.InventoryApplicationAdd")'))
        application_inventory = result.fetchall()

        if len(application_inventory) == 0:
            print("Application inventory events not recorded in this database. Will not create CSV")
            return 0
        else:
            print(f"{len(application_inventory)} events related to application inventory found. Extracting & writing to CSV")
            application_inventory_csv = open(os.path.join(self.output_directory,"Application Inventory.csv"),"w", newline='')
            application_inventory_csv_writer = csv.writer(application_inventory_csv, dialect='excel')
            application_inventory_csv_writer.writerow(["Application Name", "Installation Directory", "Installation Timestamp (UTC)", "Publisher", "Application Version", "SID"])

            count = 0
            for apps in application_inventory:
                row_list = []
                temp_json = json.loads(apps[1])
                row_list.append(temp_json['data']['Name'])
                row_list.append(temp_json['data']['RootDirPath'])
                row_list.append(temp_json['data']['InstallDate'])
                row_list.append(temp_json['data']['Publisher'])
                row_list.append(temp_json['data']['Version'])
                row_list.append(apps[0])
                if len(set(row_list)) != 1:
                    application_inventory_csv_writer.writerow(row_list)
                    count += 1
            application_inventory_csv.close()
            return count

    def application_execution(self):
        result = self.session.execute(sql.text('SELECT events_persisted.sid, events_persisted.payload from events_persisted inner join event_tags on events_persisted.full_event_name_hash = event_tags.full_event_name_hash inner join tag_descriptions on event_tags.tag_id = tag_descriptions.tag_id where (tag_descriptions.tag_id = 25 and events_persisted.full_event_name="Win32kTraceLogging.AppInteractivitySummary")'))
        execution_list = result.fetchall()

        if len(execution_list) == 0:
            print("Win32k.TraceLogging.AppInteractivitySummary not recorded in this database. Will not create CSV")
            return 0
        else:
            print(f"{len(execution_list)} events related to application execution found. Extracting & writing to CSV")
            execution_list_csv = open(os.path.join(self.output_directory, "Application Execution.csv"), "w", newline='')
            execution_list_csv_writer = csv.writer(execution_list_csv, dialect='excel')
            execution_list_csv_writer.writerow(["Binary Name", "Execution Timestamp (UTC)", "SHA1 Hash", "Compiler Timestamp (UTC)", "SID"])

            count = 0
            for binaries in execution_list:
                row_list = []
                temp_json = json.loads(binaries[1])
                temp_binary_list = temp_json['data']['AppId'].split('!')

                if temp_binary_list[0][0] == "W":
                    binary_hash = temp_binary_list[1][4:]
                    compiler_timestamp = temp_json['data']['AppVersion'].split('!')[0].replace("/","-").replace(":", " ", 1)
                    binary_name = temp_json['data']['AppVersion'].split('!')[2]
                elif temp_binary_list[0][0] == "U":
                    binary_hash = ""
                    compiler_timestamp = temp_json['data']['AppVersion'].split('!')[1].replace("/","-").replace(":", " ", 1)
                    binary_name = temp_json['data']['AppVersion'].split('!')[3]

                row_list.append(binary_name)
                row_list.append(temp_json['time'].replace("T"," ").replace("Z",""))
                row_list.append(binary_hash)
                row_list.append(compiler_timestamp)
                row_list.append(binaries[0])
                execution_list_csv_writer.writerow(row_list)
                count += 1
            execution_list_csv.close()
            return count

    def user_defaults(self):
        result = self.session.execute(sql.text('SELECT events_persisted.sid, events_persisted.payload from events_persisted inner join event_tags on events_persisted.full_event_name_hash = event_tags.full_event_name_hash inner join tag_descriptions on event_tags.tag_id = tag_descriptions.tag_id where (tag_descriptions.tag_id = 11 and events_persisted.full_event_name = "Census.Userdefault")'))
        defaults_list = result.fetchall()
        if len(defaults_list) == 0:
            print("Device census events relating to user default settings not recorded in database. Will not create text file")
            return 0
        else:
            print(f"{len(defaults_list)} events related to user default app preferences found. Extracting and writing to text file")
            userdefaults_file = open(os.path.join(self.output_directory, "UserDefaults.txt"), "w")
            for defaults in defaults_list:
                temp_json = json.loads(defaults[1])
                userdefaults_file.write("====Record Start====\n")
                userdefaults_file.write("Recorded at: " + temp_json['time'].replace("T", " ").replace("Z", "") + "\n")
                userdefaults_file.write("Default browser: " + temp_json['data']['DefaultBrowserProgId'] + "\n")
                userdefaults_file.write("---Default Apps---\n")
                temp_list = temp_json['data']['DefaultApp'].split('|')
                for apps in temp_list:
                    userdefaults_file.write(apps + "\n")
                userdefaults_file.write("====Record End====\n\n")
            userdefaults_file.close()
            return len(defaults_list)

    def wifi_connected_events(self):
        result = self.session.execute(sql.text('SELECT events_persisted.payload from events_persisted inner join event_tags on events_persisted.full_event_name_hash = event_tags.full_event_name_hash inner join tag_descriptions on event_tags.tag_id = tag_descriptions.tag_id where (tag_descriptions.tag_id = 11 and events_persisted.full_event_name = "Microsoft.OneCore.NetworkingTriage.GetConnected.WiFiConnectedEvent")'))
        wifi_connections_list = result.fetchall()

        if len(wifi_connections_list) == 0:
            print("WiFi connection events have not been recorded in the database. Will not create CSV")
            return 0
        else:
            print(f"{len(wifi_connections_list)} events associated with successful WiFi connections found. Extracting and writing to CSV")

            wifi_connections_file = open(os.path.join(self.output_directory, "WiFi Successful Connections.csv"), "w", newline='')
            wifi_connections_csv_writer = csv.writer(wifi_connections_file, dialect='excel')
            wifi_connections_csv_writer.writerow(["WiFi SSID", "WiFi BSSID", "WiFi Connection Time (UTC)", "AP Manufacturer", "AP Model Name", "AP Model No.", "Authentication Algorithm", "Cipher Algo"])

            count = 0
            for wifi in wifi_connections_list:
                row_list = []
                temp_json = json.loads(wifi[0])
                row_list.append(temp_json['data']['ssid'])
                row_list.append(temp_json['data']['bssid'])
                row_list.append(temp_json['time'].replace('T', " ").replace('Z', ""))
                row_list.append(temp_json['data']['apManufacturer'])
                row_list.append(temp_json['data']['apModelName'])
                row_list.append(temp_json['data']['apModelNum'])
                row_list.append(temp_json['data']['authAlgo'])
                row_list.append(temp_json['data']['cipherAlgo'])
                wifi_connections_csv_writer.writerow(row_list)
                count += 1
            wifi_connections_file.close()
            return count

    def srum_app_activity(self):
        result = self.session.execute(sql.text('SELECT events_persisted.sid, events_persisted.payload from events_persisted inner join event_tags on events_persisted.full_event_name_hash = event_tags.full_event_name_hash inner join tag_descriptions on event_tags.tag_id = tag_descriptions.tag_id where (tag_descriptions.tag_id = 24 and events_persisted.full_event_name = "Microsoft.Windows.SRUM.Telemetry.AppTimelines")'))
        srum_app_activity_list = result.fetchall()

        if (len(srum_app_activity_list) == 0):
            print("Application activity fetched from SRUM not recorded in database. Will not create CSV")
            return 0
        else:
            print(f"{len(srum_app_activity_list)} events associated with application activity within SRUM found. Extracting and writing to CSV")
            SRUMAppActivity_file = open(os.path.join(self.output_directory, "SRUM Application Execution Activity.csv"), "w", newline='')
            SRUMAppActivity_csv_writer = csv.writer(SRUMAppActivity_file, dialect='excel')

            SRUMAppActivity_csv_writer.writerow(["SID", "EventTranscriptDB Record Time (UTC)", "Application Start Time (UTC)", "Application Name", "Compiler Timestamp (UTC)"])

            count = 0
            for event in srum_app_activity_list:
                temp_json = json.loads(event[1])

                for apps in temp_json['data']['records']:
                    row_list = []
                    row_list.append(event[0])
                    row_list.append(temp_json['time'].replace("T", " ").replace("Z",""))
                    row_list.append(apps['startTime'].replace("T", " ").replace("z", ""))

                    if "W:" in apps['appId']:
                        row_list.append(apps['appId'][4:])
                        row_list.append(apps['appVer'].split('!', 1)[0].replace("/", "-").replace(":", " ", 1))
                    elif "U:" in apps['appId']:
                        row_list.append(apps['appId'][2:])
                        row_list.append(apps['appVer'].split('!')[1].replace("/", "-").replace(":", " ", 1))
                    else:
                        row_list.append(apps['appId'])
                        row_list.append("N/A")
                    SRUMAppActivity_csv_writer.writerow(row_list)
                    count += 1
            SRUMAppActivity_file.close()
            return count

    def wlan_scan_results(self):
        result = self.session.execute(sql.text('SELECT events_persisted.sid, events_persisted.payload from events_persisted inner join event_tags on events_persisted.full_event_name_hash = event_tags.full_event_name_hash inner join tag_descriptions on event_tags.tag_id = tag_descriptions.tag_id where (tag_descriptions.tag_id = 11 and events_persisted.full_event_name = "WlanMSM.WirelessScanResults")'))
        wlan_scan_list = result.fetchall()

        if len(wlan_scan_list) == 0:
            print("Events associated with WLAN (WiFi) scan not recorded in database. Will not create CSV")
            return 0
        else:
            print(f"{len(wlan_scan_list)} events associated to WLAN scan found in database. Extracting and writing to CSV")

            wlan_scan_file = open(os.path.join(self.output_directory, "WLAN Scan Results.csv"), "w", newline='')
            wlan_scan_csv_writer = csv.writer(wlan_scan_file, dialect='excel')

            wlan_scan_csv_writer.writerow(["SSID", "MAC Address", "Scan Record Timestamp (UTC)", "Interface GUID"])

            count = 0
            for scan in wlan_scan_list:
                temp_json = json.loads(scan[1])

                for devices in temp_json['data']['ScanResults'].split('\n'):
                    row_list = []
                    wlan_scan_entry = devices.split('\t')
                    if wlan_scan_entry[0] != '':
                        row_list.append(wlan_scan_entry[0])
                        row_list.append(wlan_scan_entry[2])
                        row_list.append(temp_json['time'].replace("T", " ").replace("Z", ""))
                        row_list.append(temp_json['data']['InterfaceGuid'])
                        wlan_scan_csv_writer.writerow(row_list)
                        count += 1
                    else:
                        continue
            wlan_scan_file.close()
            return count

    def srum_network_usage(self):
        result = self.session.execute(sql.text('SELECT events_persisted.sid, events_persisted.payload from events_persisted inner join event_tags on events_persisted.full_event_name_hash = event_tags.full_event_name_hash inner join tag_descriptions on event_tags.tag_id = tag_descriptions.tag_id where (tag_descriptions.tag_id = 24 and events_persisted.full_event_name = "Microsoft.Windows.SrumSvc.DataUsageAggregateTimer")'))
        network_usage_list = result.fetchall()

        if len(network_usage_list) == 0:
            print("Events associated with application network usage (from SRUM) not recorded in database. Will not create CSV.")
            return 0
        else:
            print(f"{len(network_usage_list)} events associated to App network usage found. Extracting and writing to CSV")

            network_usage_file = open(os.path.join(self.output_directory, "SRUM Application Network Usage.csv"), "w", newline='')
            net_usage_csv_writer = csv.writer(network_usage_file, dialect='excel')

            net_usage_csv_writer.writerow(["Event Recorded Timestamp (UTC)", "Application Name", "Bytes Sent", "Bytes Received", "Interface GUID", "SID"])

            count = 0
            for event in network_usage_list:
                row_list = []
                temp_json = json.loads(event[1])
                row_list.append(temp_json['time'].replace("T"," ").replace("Z", ""))
                row_list.append(temp_json['data']['applicationName'])
                row_list.append(temp_json['data']['bytesSent'])
                row_list.append(temp_json['data']['bytesRecieved'])
                row_list.append(temp_json['data']['interfaceGuid'])
                row_list.append(event[0])
                net_usage_csv_writer.writerow(row_list)
                count += 1
            network_usage_file.close()
            return count

class FileSigExtractor:
    def __init__(self, directory, output_directory):
        self.directory = directory
        self.output_directory = output_directory
        self.file_list = []
        self.large_files_list = []
        self.empty_files_list = []
        self.error_files = []
        
    def analyze(self):
        """Process all files in the specified directory and extract signatures"""
        print("\nAnalyzing files in directory:", self.directory)
        self._scan_directory()
        
        # Handle large files
        if len(self.large_files_list) > 0:
            print(f"{len(self.large_files_list)} Large files found. Will be ignored. Written to 'Large-Files-Ignored.txt'")
            large_file_writer = open(os.path.join(self.output_directory, "Large-Files-Ignored.txt"), "w")
            large_file_writer.write('\n'.join(self.large_files_list))
            large_file_writer.close()

        # Handle empty files
        if len(self.empty_files_list) > 0:
            print(f"{len(self.empty_files_list)} Empty files found. Will be ignored. Written to 'Empty-Files.txt'")
            empty_file_writer = open(os.path.join(self.output_directory, "Empty-Files.txt"), "w")
            empty_file_writer.write('\n'.join(self.empty_files_list))
            empty_file_writer.close()
            
        # Process and categorize files
        known_files, unknown_files = self._process_files()
        
        # Write errors to file
        if len(self.error_files) > 0:
            errors = open(os.path.join(self.output_directory, "Errors-Encountered.txt"), "w")
            errors.write('\n'.join(self.error_files))
            errors.close()
            
        return {
            "total_files_scanned": len(self.file_list),
            "large_files": len(self.large_files_list),
            "empty_files": len(self.empty_files_list),
            "known_signatures": len(known_files),
            "unknown_signatures": len(unknown_files),
            "errors": len(self.error_files)
        }
        
    def _scan_directory(self):
        """Walks through the directory and categorizes files"""
        for root, dirs, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.join(root, file)

                try:
                    size = os.stat(file_path).st_size

                    if size == 0:
                        self.empty_files_list.append(file_path)
                    elif size/(1024*1024) >= 512:  # Files larger than 512MB
                        self.large_files_list.append(file_path)
                    else:
                        self.file_list.append(file_path)
                except OSError:
                    self.error_files.append(f"Encountered OSError scanning {file_path}")
    
    def _process_files(self):
        """Process files and extract their signatures"""
        known_files = []
        unknown_files = []
        
        # Setup output files
        unknown_file_path = os.path.join(self.output_directory, "Unknown-Files.csv")
        known_file_path = os.path.join(self.output_directory, "Matched-Files.csv")
        
        with open(unknown_file_path, "w", newline='') as unknown_f, open(known_file_path, "w", newline='') as known_f:
            unknown_writer = csv.writer(unknown_f, dialect='excel')
            known_writer = csv.writer(known_f, dialect='excel')
            
            # Write headers
            headers = ["File Path", "Original Extension", "File Type"]
            unknown_writer.writerow(headers)
            known_writer.writerow(headers)
            
            # Process each file
            for file_path in self.file_list:
                try:
                    file_info = [
                        file_path,
                        os.path.splitext(file_path)[1],
                        magic.from_buffer(open(file_path, "rb").read(2048))
                    ]
                    
                    if file_info[2] == "data":
                        unknown_writer.writerow(file_info)
                        unknown_files.append(file_path)
                    else:
                        known_writer.writerow(file_info)
                        known_files.append(file_path)
                        
                except PermissionError:
                    self.error_files.append(f"Encountered PermissionError for {file_path}. Cannot open.")
                except FileNotFoundError:
                    self.error_files.append(f"Encountered FileNotFoundError for {file_path}. Cannot open.")
                except OSError:
                    self.error_files.append(f"Encountered OSError for {file_path}. Cannot open.")
        
        print(f"Scanned {len(self.file_list)} files within {self.directory}")
        print(f"Output for known signatures written to {known_file_path}")
        print(f"Output for unknown signatures written to {unknown_file_path}")
        
        return known_files, unknown_files

def main():
    parser = argparse.ArgumentParser(
        description='''Windows Forensic Tool - Combines EventTranscript.db analysis and file signature extraction capabilities''')
    # Main command group
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # EventTranscript parser
    event_parser = subparsers.add_parser('event', help='Parse EventTranscript.db')
    event_parser.add_argument('-f', '--file', required=True, help="Path to EventTranscript.db")
    event_parser.add_argument('-o', '--output-dir', required=True, help="Output directory for CSV files")
    
    # File signature parser
    file_parser = subparsers.add_parser('filesig', help='Extract file signatures')
    file_parser.add_argument('-d', '--directory', required=True, help="Directory to scan")
    file_parser.add_argument('-o', '--output-dir', required=True, help="Output directory for CSV files")
    
    # Combined operation
    combined_parser = subparsers.add_parser('combined', help='Run both analyses')
    combined_parser.add_argument('-f', '--file', required=True, help="Path to EventTranscript.db")
    combined_parser.add_argument('-d', '--directory', required=True, help="Directory to scan")
    combined_parser.add_argument('-o', '--output-dir', required=True, help="Output directory for CSV files")
    
    args = parser.parse_args()
    
    print("\nWindows Forensic Analysis Tool")
    print("==============================")
    print("==============================\n")
    
    # Create output directory if it doesn't exist
    if not os.path.isdir(args.output_dir):
        os.makedirs(args.output_dir)
    
    # Process based on command
    if args.command == 'event':
        if os.path.exists(args.file):
            analyzer = EventTranscriptAnalyzer(args.file, args.output_dir)
            results = analyzer.analyze()
            
            print("\nSummary:")
            for category, count in results.items():
                if count > 0:
                    print(f"- {category}: {count} events processed")
        else:
            print(f"Error: EventTranscript.db file not found at {args.file}")
            
    elif args.command == 'filesig':
        extractor = FileSigExtractor(args.directory, args.output_dir)
        results = extractor.analyze()
        
        print("\nSummary:")
        print(f"- Total files scanned: {results['total_files_scanned']}")
        print(f"- Files with known signatures: {results['known_signatures']}")
        print(f"- Files with unknown signatures: {results['unknown_signatures']}")
        print(f"- Large files skipped: {results['large_files']}")
        print(f"- Empty files skipped: {results['empty_files']}")
        print(f"- Errors encountered: {results['errors']}")
        
    elif args.command == 'combined':
        print("Running combined analysis...")
        
        if not os.path.exists(args.file):
            print(f"Error: EventTranscript.db file not found at {args.file}")
            return
            
        # Create subdirectories for each analysis
        event_dir = os.path.join(args.output_dir, "EventTranscript")
        filesig_dir = os.path.join(args.output_dir, "FileSigExtractor")
        
        if not os.path.exists(event_dir):
            os.makedirs(event_dir)
        if not os.path.exists(filesig_dir):
            os.makedirs(filesig_dir)
            
        # Run both analyses
        analyzer = EventTranscriptAnalyzer(args.file, event_dir)
        event_results = analyzer.analyze()
        
        extractor = FileSigExtractor(args.directory, filesig_dir)
        filesig_results = extractor.analyze()
        
        # Print combined summary
        print("\nCombined Analysis Summary:")
        print("==========================")
        print("EventTranscript Analysis:")
        for category, count in event_results.items():
            if count > 0:
                print(f"- {category}: {count} events processed")
                
        print("\nFile Signature Analysis:")
        print(f"- Total files scanned: {filesig_results['total_files_scanned']}")
        print(f"- Files with known signatures: {filesig_results['known_signatures']}")
        print(f"- Files with unknown signatures: {filesig_results['unknown_signatures']}")
        print(f"- Large files skipped: {filesig_results['large_files']}")
        print(f"- Empty files skipped: {filesig_results['empty_files']}")
        print(f"- Errors encountered: {filesig_results['errors']}")
        
        print(f"\nAll results saved to {args.output_dir}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

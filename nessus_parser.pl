#!/usr/bin/perl
use XML::TreePP;
use Excel::Writer::XLSX;
use Data::Dumper;		# Used for debugging
use File::Basename qw/basename/;
use POSIX qw(strftime);

# Add any pluginID to the hash to prevent its processing/output
my %restrictedPlugins = (
	'33929' => 1,	# PCI DSS compliance
	'60020' => 1,   # PCI DSS Compliance : Handling False Positives
        '56209' => 1,   # PCI DSS Compliance : Remote Access Software Has Been Detected
	'33931' => 1,   # PCI DSS Compliance: Test Requirements
	'33930' => 1,   # PCI DSS Compliance: Passed
	'108714' => 1,  # PCI DSS Compliance : Scan Interference
        '108591' => 1,  # PCI DSS Compliance: OS vulnerabilities detected in banner reporting
#	'51192' => 1,	# SSL Certificate Cannot Be Trusted - handled by Entrust
#	'57582' => 1,   # SSL Self-Signed Certificate - handled by Entrust
#       '45411' => 1,   # SSL Certificate with Wrong Hostname - handled by Entrust
        '58601' => 1,   # ASP.NET ValidateRequest - doesn't validate and is paranoia reporting due to PCI DSS check 
        '64589' => 1,   # MS-DOS DOS PCI Check - remove due to being PCI and DOS is not concern for data loss. Physical attacks also need COM ports.
);

my %hpovPlugins = (
    '35291' => 1, 
    '51192' => 1,
    '69551' => 1,
    '57582' => 1, 
    '45411' => 1,
    );

my %customGuidance = (
    '57608' => "Enforce message signing in the host's configuration.",
    '57690' => "Submit a request",
    '58453' => "Enable Network Level Authentication (NLA) on the remote RDP server. This is generally done on the 'Remote' tab of the 'System' settings on Windows.",
    '65821' => "Reconfigure the affected application, if possible, to avoid use of RC4 ciphers. Consider using TLS 1.2 with AES-GCM suites subject to browser and web server support.",
    '78628' => "Apply the relevant update referenced in HP Security Bulletin HPSBMU03126.",
    '30218' => "For Windows 2008 servers once joined to the domain, submit a request.");

# Process cli input
if (@ARGV+0 < 1) {
	print "syntax: $0 <file/directory>\n";
	exit(0);
}

my $arg1 = shift @ARGV;
my $directory = "";
my $filename = "";
my @dataRows;

if (-d $arg1) {	# It's not a file, it's a directory
	$directory = $arg1;
	$filename = "nessus_findings.xlsx";	# Required to generate output file
	my @dirListing = `ls $directory/*.nessus`;
	while (@dirListing) {
		$fname = shift @dirListing;
		chomp $fname;
		my $tpp = XML::TreePP->new();
		my $tree = $tpp->parsefile("$fname");
		my $report = $tree->{NessusClientData_v2}->{Report};
		my @tmpDataRows = ProcessNessusReport($report);
		push @dataRows, @tmpDataRows;
	}

} else {
	$filename = $arg1;
	# Process Nessus findings
	my $tpp = XML::TreePP->new();

	# DOP: If there's only one host, ReportHost is returned as just
	# a hash, rather than an array of hashes.  Need to force it.
	$tpp->set( force_array => [ 'ReportHost' ] );
	my $tree = $tpp->parsefile($filename);
	my $report = $tree->{NessusClientData_v2}->{Report};

	@dataRows = ProcessNessusReport($report);

}

# Generate XLSX File
my @xlsxRows;
push @xlsxRows, [("Finding #", "State", "Status", "Finding Title", "System Name", "System IP", "Port", 
	"Technical Risk", "Business Risk", "CVSS Base Score", "CVE", "Description", "Recommendations", "Notes", "Detail")];

push @xlsxRows, @dataRows;

my $xlsxFilename = basename($filename, ('.nessus')) . ".xlsx";

my $workbook = Excel::Writer::XLSX->new($xlsxFilename);
my $worksheetTestInfo = $workbook->add_worksheet("TestInfo");
my $worksheetServerList = $workbook->add_worksheet("Server List");
my $worksheet = $workbook->add_worksheet("Vuln List");

##  Remote the write_url() from the default write handler
$worksheet->add_write_handler( qr[^[fh]tt?ps?://], \&write_no_url );
sub write_no_url {
    my $worksheet = shift;
    return $worksheet->write_string( @_ );
}

my $infocol = [("Project", "Test Type", "Completion Date", "Contacts", "Testers", "Methodology", "",
	       "XLS sheet contents","   Test Info:", "   Server List:", "   Vuln List:", "" ,"Additional Notes")];
$worksheetTestInfo->write_col(0, 0, $infocol);

my $infocol = [(""       , "PCI Pentest",strftime("%m/%d/%Y", localtime), "", "", "automated nessus and manual testing", "",
	       "","This Page", "List of in-scope targets as defined by Project Team, this list includes all systems tested whether vulnerabilities were found or not.", "All vulnerabilities found, itemized as best as possible to one finding per Host:Port. Status of vulnerabilities after retesting.", "" ,"")];
$worksheetTestInfo->write_col(0, 1, $infocol);

my $slistrow = [("IP Address", "Device Name")];
$worksheetServerList->write_row(0, 0, $slistrow);

my $row = 0;
foreach my $row_data (@xlsxRows) {
	$worksheet->write_row($row++, 0, $row_data);
}

$workbook->close();

exit(0);	# Unnecessary

sub ProcessNessusReport {
	my ($report) = @_;

	my @data_rows;
	my $reportHost = $report->{ReportHost};

	foreach my $host (@$reportHost) {
		my $hostname = $host->{-name};
		my $hostIP = "";
		my $hostProperties = $host->{HostProperties}->{tag};
		foreach my $property (@$hostProperties) {
			if ($property->{-name} eq "host-ip") {
				$hostIP = $property->{"#text"};
				last;
			}
		}

		$reportItems = $host->{ReportItem};
		#Make sure there are still some items to processes
		if ( ref( $reportItems  ) eq "ARRAY" ) {
		   foreach my $reportItem (@$reportItems) {
			
			my $riskFactor = $reportItem->{risk_factor};	# Feed into risk calculation
			my $pluginID = $reportItem->{-pluginID};
			
			# Process reportItems with riskFactor other than None, and not in restrictedPlugins
			if ( ($riskFactor ne "None") && !(defined($restrictedPlugins{$pluginID})) ) {

				my $port = $reportItem->{-port};
				my $protocol = $reportItem->{-protocol};

				my $pluginName = $reportItem->{-pluginName};	# Finding Title
				my $description = $reportItem->{description};	# Description
				my $solution = "";
				if (defined($customGuidance{$pluginID})) {
				    $solution = $customGuidance{$pluginID};
				} else {
				    $solution = $reportItem->{solution};        # Recommendation
				}
				my $cvssScore = $reportItem->{cvss_base_score};	# CVSS Base Score
				my $detail = $reportItem->{plugin_output};	# Specific Details
				my $seeAlso = $reportItem->{see_also};		# For the Notes Column
				my @parts = split (/\n/, $seeAlso);
				$seeAlso = join (', ', @parts);			# XLSX Writer still complains, no matter what I do

				my $cve = $reportItem->{cve};			# CVEs
				my $cveText = "";

				if (ref($cve) eq 'ARRAY') {			# If $cve is an array, process it
					$cveText = join(', ', @$cve);
				} else {					# Otherwise, set $cveText
					$cveText = $cve;
				}

				my $busRiskFactor = $riskFactor;
				# Convert Medium to Moderate
				if ($riskFactor eq "Medium") {
					$busRiskFactor = "Moderate";
				}

				# Covert Crititcal to Very High
				if ($riskFactor eq "Critical") {
					$busRiskFactor = "Very High";
				}
				# Make sure it's not an hpov finding:
				unless ($port == 383 && defined($hpovPlugins{$pluginID})) {
				push @data_rows, [("Nessus-$pluginID", "validated", "open", $pluginName, $hostname, $hostIP, "$port/$protocol", 
						   $riskFactor, $busRiskFactor, $cvssScore, $cveText, $description, $solution, $seeAlso, $detail)];
				} 
			}
		   }
		}
	}

	return @data_rows;
}

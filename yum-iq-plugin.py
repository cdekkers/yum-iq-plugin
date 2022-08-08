"""This yum plugin implements vulnerability escalation using nexus_iq Server."""

from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
from yum.constants import *
from output import YumOutput
from dataclasses import dataclass
import sys
import subprocess
import os
import json

requires_api_version = '2.3'
plugin_type = (TYPE_CORE, TYPE_INTERACTIVE)
yum_output = YumOutput()

@dataclass
class NexusIQHelper:
    """A helper class for interacting with Nexus IQ"""
    hostname: str
    cli_jar_path: str = "/usr/lib/nexus-iq-cli/nexus-iq-cli.jar"
    url: str = "http://localhost:8070"
    package_file_path: str = "/tmp/yum-packages.txt"
    results_file_path: str = "/tmp/nexus_iq_cli.log"
    
    CONF_SECTION_SCAN = "scan"
    CONF_SECTION_NEXUS_IQ = "nexus_iq"

    def confBool(self, opt):
        return conduit.confBool(
            self.CONF_SECTION,
            opt,
            default=getattr(self, opt)
        )

    def confFloat(self, opt):
        return conduit.confFloat(
            self.CONF_SECTION,
            opt,
            default=getattr(self, opt)
        )
    
    def confInt(self, opt):
        return conduit.confInt(
            self.CONF_SECTION,
            opt,
            default=getattr(self, opt)
        )

    def confString(self, opt):
        return conduit.confString(
            self.CONF_SECTION,
            opt,
            default=getattr(self, opt)
        )

    def run(self):
        subprocess.call([
            "/usr/bin/java",
            "-jar", self.confString("cli_jar_path"),
            "-i", self.hostname,
            "-s", self.confString("url"),
            "-a", f"{self.confString('username')}:{self.confString('password')}",
            "-r", self.confString("results_file_path"),
            self.confString("package_file_path")
        ])

def postresolve_hook(conduit):
    if not conduit.confBool(
        "scan",
        "pre_scan",
        default=False
    ):
        return

    safe = False
    while not safe:

        # Retrieve the list of packages that yum will install.
        installable_packages = conduit.getTsInfo().getMembersWithState(output_states=TS_INSTALL_STATES)
        
        # Get the location to the yum packages list file.
        package_file_path = conduit.confString(
            "nexus_iq",
            "package_file_path",
            default="/tmp/yum-packages.txt"
        )

        # Temporarily reroute stdout to file and write packages there.
        with open(package_file_path, 'w') as package_file:
            
            # Save reference to system stdout.
            orig_stdout = sys.stdout
            
            try:
                # Temporarily route system stdout to package file.
                sys.stdout = package_file
                
                # Write the list of packages to be installed to stdout.
                for package in installable_packages:
                    yum_output.simpleList(package.po)
            
            # Finally, restore the system stdout.
            finally:
                sys.stdout = orig_stdout

        # Get CLI call parameters
        cli_jar_path = conduit.confString(
            "nexus_iq",
            "cli_jar_path",
            default="/usr/lib/nexus-iq-cli/nexus-iq-cli.jar"
        )
        hostname = os.environ["HOSTNAME"]
        iq_server_url = conduit.confString(
            "nexus_iq",
            "url",
            default="http://localhost:8070"
        )

        username = conduit.confString(
            "nexus_iq",
            "username",
            default="admin"
        )
        password = conduit.confString(
            "nexus_iq",
            "password",
            default="admin123"
        )
        credentials = f"{username}:{password}"
        results_file_path = conduit.confString(
            "nexus_iq",
            "results_file_path",
            default="/tmp/cli.log"
        )

        # Run nexus_iq CLI
        subprocess.call(["/usr/bin/java", "-jar", cli_jar_path, "-i", hostname,"-s",iq_server_url, "-a", credentials, "-r", results_file_path, package_file_path])
        ## List hits from scan results
        scan_hits = []
        #### TEST CODE ####
        # results_file_path = "test.json"
        #### END ####
        f = open(results_file_path, 'r')
        results = json.load(f)
        strict_mode = conduit.confBool("scan","strict_mode", default=False)
        # If an error occurs...
        if 'errorMessage' in results:
            # ...and we're in strict mode, fail yum
            if strict_mode:
                raise PluginYumExit('Vulnerability scanning failed: '+results['errorMessage'])
            # else break out of the loop
            break
        
        if conduit.confBool("scan", "block_pre_scan", default=False):
            # Find the components for which a policy is set to fail
            for alert in results['policyEvaluationResult']['alerts']:
                if {'actionTypeId': 'fail', 'target': None} in alert['actions']:
                    for componentFact in alert['trigger']['componentFacts']:
                        # Get the component name and add is to the scan hits
                        scan_hits.append(componentFact['componentIdentifier']['coordinates']['artifactId'])
        
        # The banned packages are the packages for which the name has a match in the scan hits
        bannedPackages = [x for x in packages if x.po.name in scan_hits]
        #### TEST CODE ####
        # bannedPackages.append(packages[24])
        #### END ####
        
        # If there are no banned packages, we're safe
        if not bannedPackages:
            safe = True
        else:
            conduit.info(2, bannedPackages)
            # Else remove packages from the sack and the transaction
            for package in bannedPackages:
                conduit.delPackage(package.po)
                conduit.getTsInfo().deselect(package.po.name)
            # Rerun the dependency resolver until we are safe
            conduit._base.resolveDeps(True)
    
    # Mark the transaction as changed so yum will run the resolver again otherwise yum won't notice the banned components
    conduit.getTsInfo().changed=True

def postverifytrans_hook(conduit):

    ## Run post-install based on configuration.
    if not conduit.confBool("scan", "post_scan", default=True):
        return

    # Get the location to the yum packages list file
    package_file_path = conduit.confString("nexus_iq","package_file_path", default="/tmp/yum-packages.txt")
    # Route stdout to file
    orig_stdout = sys.stdout
    f = open(package_file_path, 'w')
    sys.stdout = f
    # write the list of packages to be installed to stdout
    for package in conduit.getRpmDB().returnPackages():
        yum_output.simpleList(package)
    # Reset stdout
    sys.stdout = orig_stdout
    f.close()
    # Get CLI call parameters
    cli_jar_path = conduit.confString("nexus_iq","cli_jar_path",default="/usr/lib/nexus-iq-cli/nexus-iq-cli.jar")
    hostname = os.environ["HOSTNAME"]
    iq_server_url = conduit.confString("nexus_iq","url", default="http://locahost:8070")
    credentials = conduit.confString("nexus_iq","username",default="admin") + ":" + conduit.confString("nexus_iq","password",default="admin123")
    # Run nexus_iq CLI
    subprocess.call(["/usr/bin/java", "-jar", cli_jar_path, "-i", hostname,"-s",iq_server_url, "-a", credentials, package_file_path])
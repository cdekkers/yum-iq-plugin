from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
from yum.constants import *
from output import YumOutput
import sys
import subprocess
import os
import json

requires_api_version = '2.3'
plugin_type = (TYPE_CORE, TYPE_INTERACTIVE)
yum_output = YumOutput()

def postresolve_hook(conduit):
    pre_scan = conduit.confBool("scan behaviour","pre_scan", default=False)
    if pre_scan:
        safe = False
        while not safe:
            # Get the list of packages that are going to be installed with the yum call
            packages = conduit.getTsInfo().getMembersWithState(output_states=TS_INSTALL_STATES)
            ## Do a scan
            # Get the location to the yum packages list file
            package_file_path = conduit.confString("nexus iq","package_file_path", default="/tmp/yum-packages.txt")
            # Route stdout to file
            orig_stdout = sys.stdout
            f = open(package_file_path, 'w')
            sys.stdout = f
            # write the list of packages to be installed to stdout
            for package in packages:
                yum_output.simpleList(package.po)
            # Reset stdout
            sys.stdout = orig_stdout
            f.close()
            # Get CLI call parameters
            cli_jar_path = conduit.confString("nexus iq","cli_jar_path",default="/usr/lib/nexus-iq-cli/nexus-iq-cli.jar")
            hostname = os.environ["HOSTNAME"]
            iq_server_url = conduit.confString("nexus iq","url")
            credentials = conduit.confString("nexus iq","username",default="admin") + ":" + conduit.confString("nexus iq","password",default="admin123")
            results_file_path = conduit.confString("nexus iq","results_file_path",default="/tmp/cli.log")
            # Run Nexus IQ CLI
            subprocess.call(["/usr/bin/java", "-jar", cli_jar_path, "-i", hostname,"-s",iq_server_url, "-a", credentials, "-r", results_file_path, package_file_path])
            ## List hits from scan results
            scan_hits = []
            #### TEST CODE ####
            # results_file_path = "test.json"
            #### END ####
            f = open(results_file_path, 'r')
            results = json.load(f)
            strict_mode = conduit.confBool("scan behaviour","strict_mode", default=False)
            # If an error occurs...
            if 'errorMessage' in results:
                # ...and we're in strict mode, fail yum
                if strict_mode:
                    raise PluginYumExit('Vulnerability scanning failed: '+results['errorMessage'])
                # else break out of the loop
                break
            block_pre_scan = conduit.confBool("scan behaviour","block_pre_scan", default=False)
            if block_pre_scan:
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
    post_scan = conduit.confBool("scan behaviour","post_scan", default=True)
    if post_scan:
        ## Run post install scan
        # Get the location to the yum packages list file
        package_file_path = conduit.confString("nexus iq","package_file_path", default="/tmp/yum-packages.txt")
        # Route stdout to file
        orig_stdout = sys.stdout
        f = open(package_file_path, 'w')
        sys.stdout = f
        # write the list of packages to be installed to stdout
        for package in conduit.getRpmDB().returnPackages():
            yum_output.simpleList(package.po)
        # Reset stdout
        sys.stdout = orig_stdout
        f.close()
        # Get CLI call parameters
        cli_jar_path = conduit.confString("nexus iq","cli_jar_path",default="/usr/lib/nexus-iq-cli/nexus-iq-cli.jar")
        hostname = os.environ["HOSTNAME"]
        iq_server_url = conduit.confString("nexus iq","url")
        credentials = conduit.confString("nexus iq","username",default="admin") + ":" + conduit.confString("nexus iq","password",default="admin123")
        # Run Nexus IQ CLI
        subprocess.call(["/usr/bin/java", "-jar", cli_jar_path, "-i", hostname,"-s",iq_server_url, "-a", credentials, package_file_path])
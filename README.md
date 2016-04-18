<img alt="Splunk Logo" src="https://github.com/Dynatrace/DCRUM-Splunk-Application/blob/images/splunk-logo.png" width="360">

# DCRUM-Splunk-Application

The Dynatrace DC RUM Splunk Application provides a seamless way of storing DC RUM data in Splunk.

## What is Dynatrace DC RUM?

[Data Center Real User Monitoring (DC RUM)](http://www.dynatrace.com/en/data-center-rum/) is an effective, non-intrusive choice for monitoring business applications that are accessed by employees, partners, and customers outside the corporate enterprise or from the corporate network (intranet or extranet).

## How to use Splunk with Dynatrace DC RUM?

See detailed instructions on the [Splunk plugin for DC RUM](https://community.dynatrace.com/community/display/PUBDCRUM/Splunk+plugin+for+DC+RUM)
plugin page.

## Where can I find the newest version of the Dynatrace-built Splunk application?

See [Splunk plugin for DC RUM](https://community.dynatrace.com/community/display/PUBDCRUM/Splunk+plugin+for+DC+RUM)
plugin page.

## How can I build the DC RUM Splunk application from sources?

1. You must have [Git](https://git-scm.com/) and [Apache Ant](http://ant.apache.org/) installed.
1. Clone the git repository to your computer:
```
git clone https://github.com/Dynatrace/Dynatrace-DCRUM-Splunk-Application.git
```
3. In the the DCRUM-Splunk-Application directory, run:
```
ant -f zipScript.xml
```
4. You will geqt a `DCRUMSplunkApplicationInstaller-1.custom.spl` file in the `DCRUMSplunkApplication`
 directory created which you can deploy into your Splunk server.

## Problems? Questions? Suggestions?

This offering is [Dynatrace Community Supported](https://community.dynatrace.com/community/display/DL/Support+Levels#SupportLevels-Communitysupported/NotSupportedbyDynatrace(providedbyacommunitymember)).
Feel free to share any problems, questions, and suggestions with your peers on the Dynatrace Community
[Data Center RUM Forum](https://answers.dynatrace.com/spaces/159/index.html).

## License

Licensed under the BSD License. See the [LICENSE](https://github.com/Dynatrace/DCRUM-Splunk-Application/blob/master/LICENSE)
file for details.

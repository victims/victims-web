victims-web [![Build Status](https://travis-ci.org/victims/victims-web.png)](https://travis-ci.org/victims/victims-web)
===========
The victims web application.
## Report an Issue
If you find an issue with the service at http://victi.ms or the code, either
* Create a new issue at https://github.com/victims/victims-web/issues
* Email vicitms@librelist.com

## Contributing
If you have a patch or a feature that you want considered to be added to the project, feel free to send us a pull request.
Make sure you run pep8 before committing.
```sh
pep8 --repeat src/
```
## Development
This is short guide on how to work on this code base.
### Requrements
Make sure the following are in your system-path:
* virtualenv (Python Virtual Environment)
* mongod (Mongo DB server)

### Set up the environment
Once you have cloned your repository, and changed into it you can just source the _start-dev-env.sh_ script. The first time you do this, it will take a bit as virtual environment setup will download all required dependices into a new env.
#### Activate the environment
```sh
source ./contrib/scripts/start-dev-env.sh
```
Once active, you should see _victims.dev_ prefixed to your terminal prompt. For example:
```sh
[abn@whippersnapper victims-web (master)]$ source ./contrib/scripts/start-dev-env.sh 
victims.dev[abn@whippersnapper victims-web (master)]$ 
```
#### Run the test suite to see if everything is in order
```sh
./contrib/scripts/run-tests.sh
```
#### Control the test database
The test database is loaded with one record, available at _test/mong_test.json_. The database can be _start/stop/restar_ using the provided script.
```sh
./contrib/scripts/mongo-db-ctl.sh <start|stop|restart>
```
This will create a new data base at _$(pwd)/testdb_ this will also contain the log files. The import only happens once. If you want to start from scratch again, just remove this directory.
#### Running the application
To test web-ui changes you might want to run the web-app on your local machine. You can do this by doing:
```sh
# Make sure the database is available, this will not do anything if it is already running
./contrib/scripts/mongo-db-ctl.sh start

# Run the app in the dev env
cd src/victims_web/
python application.py
```
You should be able to see the victims page at _http://localhost:5000/_ if everything was done correctly, with 1 hash record.

## Usage
### Secured API Access
Submission end points like ```/service/submit/archive/java``` are secured by an implementation similar to what is used by AWS. The authorization is expected in a header named ```Victims-Api```. If this is not present or if validation/authorization fails, check falls back to *BASIC AUTH*.

An example using curl is as follows:
```sh
$ curl -v -X PUT -H "Victims-Api: $APIKEY:$SIGNATURE" -H "Date: Thu, 22 Aug 2013 15:20:37 GMT" -F archive=@$ARCHIVE http://$VICTIMS_SERVER/service/submit/archive/java?version=VID\&groupId=GID\&artifactId=AID\&cves=CVE-2013-0000,CVE-2013-0001
```
#### API Key and Client Secret Key
Each account on victi.ms is allocated an API Key and Secret key by default. This can be retrieved by visiting ```https://victi.ms/account```. These can be regenerated using the form at ```https://victi.ms/account_edit```.

#### Signature
The signature is generated using ```HTTP Method```, ```Path```, ```Content-Type```, ```Date``` and the *MD5 hexdigest*.

The following is a reference implementation in python:
```py
from hmac import HMAC

def generate_signature(secret, method, path, content_type, date, data_md5):
    ordered = [method, path, content_type, date, data_md5]
    string = ''

    for content in ordered:
        if content is None:
            raise ValueError('Required header not found')
        string += str(content)

    return HMAC(
        key=bytes(secret),
        msg=string.lower(),
        digestmod=sha512
    ).hexdigest().upper()
```

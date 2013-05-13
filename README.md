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

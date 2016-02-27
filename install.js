// modified from v0.4.15 of websockets/ws

/* homedir - sindresorhus/os-homedir
The MIT License (MIT)

Copyright (c) Sindre Sorhus <sindresorhus@gmail.com> (sindresorhus.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

function homedir() {
	var env = process.env;
	var home = env.HOME;
	var user = env.LOGNAME || env.USER || env.LNAME || env.USERNAME;

	if (process.platform === 'win32') {
		return env.USERPROFILE || env.HOMEDRIVE + env.HOMEPATH || home || null;
	}

	if (process.platform === 'darwin') {
		return home || (user ? '/Users/' + user : null);
	}

	if (process.platform === 'linux') {
		return home || (process.getuid() === 0 ? '/root' : (user ? '/home/' + user : null));
	}

	return home || null;
}

function stringToBool(str) {
  return str == "true" ? true : false;
}

var spawn = require('child_process').spawn;
var path = require('path');

var json = require('./package.json');

var native = process.env['npm_package_config_native'] != null ? stringToBool(process.env['npm_package_config_native']) : process.platform !== 'win32';
if(native) {
  console.log("Building dhcurve " + json.version + " with blazing fast native extensions!");

  var new_env = {};
  Object.keys(process.env).forEach(function(name) {
    new_env[name] = process.env[name];
  });

  new_env.HOME = homedir();
  console.log(new_env);

  var gyp = spawn('node-gyp', ['rebuild'], {
    cwd: __dirname,
    env: new_env,
    shell: true
  });

  /* silence stdout
  gyp.stdout.on('data', function(data) {=
    process.stdout.write(data);
  });
  */

  gyp.stderr.on('data', function(data) {
    process.stdout.write(data);
  });

  gyp.on('exit', function(code) {
    console.log("Build of native extensions completed with status code " + code + ".");
    process.exit(0);
  });
}
else {
  console.log("Your platform can't build the native extensions, but you can still use the speedy JS fallback.");
  console.log("Use <npm install dhcurve --dhcurve:native> to override this and try to build them regardless.");
}

// modified from v0.4.15 of websockets/ws

function stringToBool(str) {
  return str == "true" ? true : false;
}

var spawn = require('child_process').spawn;

var native = process.env['npm_package_config_native'] != null ? stringToBool(process.env['npm_package_config_native']) : process.platform !== 'win32';
if(native) {
  console.log("Building dhcurve with blazing fast native extensions!");

  var gyp = spawn('node-gyp', ['rebuild'], {
    cwd: __dirname,
    env: process.env,
    shell: true
  });
  /* silence stdout
  gyp.stdout.on('data', function(data) {
    process.stdout.write(data);
  });
  */
  gyp.stderr.on('data', function(data) {
    process.stdout.write(data);
  });
  gyp.on('exit', function(code) {
    console.log("Build of native extensions completed.");
    process.exit(code);
  });
}
else {
  console.log("Your platform can't build the native extensions, but you can still use the speedy JS fallback.");
  console.log("Use <npm install dhcurve --dhcurve:native> to override this and try to build them regardless.");
}

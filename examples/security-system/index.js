var u2fc = require('u2f-client'),
    u2f = require('u2f'),
    fs = require('fs'),
    path = require('path'),
    repl = require('repl'),
    util = require('util'),
    async = require('async'),
    appId = 'node:u2f-client:examples:security-system',
    keyFile = path.join(__dirname, 'keys.json'),
    keys = [];

try {
    keys = JSON.parse(fs.readFileSync(keyFile));
    console.log('1.keys : ', keys)
}
catch (e) {}

function saveKeys() {
    fs.writeFileSync(keyFile, JSON.stringify(keys, undefined, 2));
}

// Handle user interaction requests.
u2fc.on('user-presence-required', function() {
    console.log(" -- Please touch the key");
});

u2fc.on('waiting-for-device', function() {
    console.log(" -- Please insert U2F device. Waiting "+u2fc.waitForDevicesTimeout/1000+" sec.");
});

function keyRequestCheck(appId, keyHandle, cb) {
    u2fc.check(u2f.request(appId, keyHandle), function(err, res) {
        console.log('1.keyRequestCheck check : ', appId, key.keyHandle)
        if (err) {
            console.error(err);
            return cb(false);
        }
        console.log('2.keyRequestCheck check key : ', res)
        cb(res);
    });
}
// Capture and handle device connect/disconnect events.
function deviceConnected(device) {
    console.log("\n -- U2F deviceConnected connected : ", device);
    async.filterSeries(keys, function(key, cb) {
        console.log('1.deviceConnected key : ', key)
        keyRequestCheck(appId, key.keyHandle, cb)
    }, function(approvedKeys) {
        if (!approvedKeys || !approvedKeys.length) {
            console.log(" -- No user keys found. Register with 'register <username>'.");
        } else if (approvedKeys.length == 1) {
            var key = approvedKeys[0];
            console.log(" -- Key is registered for user '"+key.user+"'. Trying to log in.");
            var req = u2f.request(appId, key.keyHandle);
            u2fc.sign(req, function(err, resp) {
                if (err) return console.error(err);
                var data = u2f.checkSignature(req, resp, key.publicKey);
                if (!data.successful) {
                    console.log(" == ACCESS DENIED == ");
                    console.log(data.errorMessage);
                } else {
                    console.log(" == ACCESS GRANTED for user "+key.user+" == ")
                }
            });

        } else {
            console.log(" -- Key is registered for users: "+ approvedKeys.map(function(k) {return k.user}).join(", "));
            console.log(" -- Type 'login <username>' with one of these usernames to get access.");
        }
    });
}

function deviceDisconnected(deviceId) {
    console.log("\n -- U2F deviceDisconnected : ", deviceId);
}

// Poll for changes in devices array.
var devicesSeen = {};
setInterval(function() {
    var devices = u2fc.devices();
    for (var i = 0; i < devices.length; i++) {
        var id = devices[i].id;
        if (!devicesSeen[id])
            setTimeout(deviceConnected, 0, devices[i]);
        else
        // console.log('1.device scan delete : ', id)
            delete devicesSeen[id];
    }
    for (var k in devicesSeen)
        deviceDisconnected(k);

    devicesSeen = {};
    for (var i = 0; i < devices.length; i++)
        {
            // console.log('2.device scan add : ', id)
            devicesSeen[devices[i].id] = true
        }
}, 200);


// Launch the REPL.
console.log("Welcome to U2F Security System example. Insert U2F key and touch it to get access granted.");
console.log("Type 'register <user>' to register currently inserted U2F device as belonging to given user.");
console.log("Type 'help' for other commands. Ctrl-D to exit.");
console.log("Registration data is kept in 'keys.json' file.");

function contains(a, obj) {
    for (var i = 0; i < a.length; i++) {
        if (a[i] === obj) {
            console.log('1.contains TRUE : ', obj)
            return true;
        }
    }
    console.log('2.contains FALSE : ', obj)
    return false;
}

repl.start({
    eval: function(cmdIn, context, filename, cb) {
        const cmd = cmdIn.replace(/\s+$/, '');
        // console.log('1.repl start : ', cmd, cmd.length)
        // for (let l=0;l<cmd.length; l++) console.log('111 -',cmd[l],'- 111')
        // const cmd = cmdIn.toString()
        const cmdList = [
            'register',
            'login',
            'remove',
            'help',
            'users',
            'devices',
            'save'
        ]
        if (!cmd || !cmd.length || !contains(cmdList, cmd)) cb()
        // cmd = cmd.slice(1, -2).split(' ').filter(Boolean);
        // console.log('1.1.repl parsed : ', cmd)
        switch (cmd) {
            case 'register':
                console.log('1.repl register : ', cmd)
                var user = cmd[1];
                console.log('2.repl register user : ', user)
                if (!user) cb()
                // Create registration request using U2F client module and send to device.
                var registerRequest = u2f.request(appId);
                console.log('3.repl registerRequest : ', registerRequest)
                u2fc.register(registerRequest, function(err, resp) {
                    if (err) return cb(err);
                    console.log('4.repl register : ', resp)
                    // Check response is valid.
                    var keyData = u2f.checkRegistration(registerRequest, resp);
                    console.log('5.repl register keyData : ', keyData)
                    if (!keyData.successful)
                        return cb(new Error(keyData.errorMessage));
                    const newKey = {
                        user: user,
                        keyHandle: keyData.keyHandle,
                        publicKey: keyData.publicKey,
                    }
                    console.log('6.repl register newKey : ', newKey)
                    keys.push(newKey);
                    saveKeys();
                    console.log('7.repl register User '+user+' successfully');
                    cb();
                })
                break
            case 'login':
                console.log('1.repl login : ', cmd)
                var user = cmd[1];
                console.log('2.repl login user : ', user)
                if (!user) cb()
                var userKeys = keys.filter(function(key) {return key.user === user;});
                if (userKeys.length == 0) {
                    console.log("Unknown user.");
                    return cb();
                }
                async.filterSeries(userKeys, function(key, cb) {
                    console.log('1.repl filterSeries : ', userKeys)
                    u2fc.check(u2f.request(appId, key.keyHandle), function(err, res) {
                        if (err) {
                            console.error(err);
                            return cb(false);
                        }
                        cb(res);
                    });
                }, function(approvedKeys) {
                    console.log('1.repl approvedKeys : ', approvedKeys)
                    if (approvedKeys.length == 0) {
                        console.log("No applicable keys found.");
                        return cb();
                    }
                    var key = approvedKeys[0];
                    var req = u2f.request(appId, key.keyHandle);
                    u2fc.sign(req, function(err, resp) {
                        if (err) return cb(err);
                        var data = u2f.checkSignature(req, resp, key.publicKey);
                        if (!data.successful) {
                            console.log(" == ACCESS DENIED == ");
                            console.log(data.errorMessage);
                        } else {
                            console.log(" == ACCESS GRANTED for user "+key.user+" == ")
                        }
                    });
                });
                break
            case 'remove':
                console.log('1.repl remove : ', cmd)
                var user = cmd[1];
                console.log('2.repl remove : ', user)
                if (!user) cb()
                var newKeys = keys.filter(function(key) {return key.user !== user;});
                if (newKeys.length == keys.length) {
                    console.log("No keys for user '"+user+"' found.");
                } else {
                    console.log((keys.length-newKeys.length)+" keys removed.");
                    keys = newKeys;
                    saveKeys();
                }
                cb();
                break
            case 'help':
                console.log('1.repl help : ', cmd)
                console.log("Commands available:");
                console.log("  help             Prints this message");
                console.log("  register <user>  Registers given user with currently connected device");
                console.log("  login <user>     Try to log in as a given user");
                console.log("  remove <user>    Clears access for given user");
                console.log("  users            Prints registered users");
                console.log("  devices          Prints currently connected devices");
                cb();
                break
            case 'users':
                console.log('1.repl users : ', cmd)
                var users = {};
                for (var i = 0; i < keys.length; i++)
                    users[keys[i].user] = true;
                console.log("Registered users: "+(Object.keys(users).join(", ") || 'none'));
                cb()
                break
            case 'devices':
                console.log('1.repl devices : ', cmd)
                cb(null, u2fc.devices())
                break
            case 'save':
                console.log('1.repl save : ', cmd)
                saveKeys()
                cb()
                break
            default:
                console.log('999.unknown command : ', cmd)
                cb(null, "Unknown command. Type 'help' to get all available commands.");
        }
        //// end switch
    },
    ignoreUndefined: true,
})
.on('exit', function() {
    console.log();
    process.exit();
});


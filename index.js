import express from 'express';
import axios from 'axios';
import knex from 'knex';
const db = knex({
    client: 'postgresql',
    connection: {
        host: '127.0.0.1',
        port: '5432',
        user: 'scphostdb',
        password: 'scphostdb',
        database: 'scphostdb'
    }
});
import { writeFile, readFile } from 'fs';
import { geolocateIp } from '@devoxa/ip-geolocation';
import dns from 'dns';
import isPortReachable from 'is-port-reachable';

var DEBUG_PLS = false;

var app = express();

app.listen(42428, () => {
 verbose("Server running on port 42428");
});

app.get("/", (req, res, next) => {
    let returnMe;
    readFile('hosts.json', (err, data) => {
        if (err) res.send(err);
        verbose(JSON.parse(data))
        res.send(JSON.parse(data))
    })
})

app.get("/keys", (req, res,next) => {
    readFile('hosts.json', (err, data) => {
        if (err) res.send(err);
        verbose(JSON.parse(data))
        let asJson = JSON.parse(data);
        let match = data.hosts.filter((e) => e.publickeystring === "edd25519:98ef402903d770aad7bf083ec458b393ad2dbf1f65d21424a8c7d83d8000fc16")
        console.log(match)
        res.send(Object.keys(asJson.hosts[0]))
    })
})

app.get("/insert", (req, res,next) => {
    readFile('hosts.json', (err, data) => {
        if (err) res.send(err);
        let asJson = JSON.parse(data);
        let match = data.hosts.filter((e) => e.publickeystring === "edd25519:98ef402903d770aad7bf083ec458b393ad2dbf1f65d21424a8c7d83d8000fc16")
        console.log(match)
        res.send(Object.keys(asJson.hosts[0]))
    })
})

const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;

async function scanHostDB() {
    verbose('scanning hosts')
    let start = +new Date();
    let end = '';
    const prevHosts = await db('hosts').select('*');
    //console.log(prevHosts)
    const blind = true;
    axios
      .get("http://localhost:4280/hostdb/active", {
        headers: {
          "User-Agent": "ScPrime-Agent",
        },
      })
      .then(async (data) => {
        verbose("ran it got it");
        verbose(data.data);
        let count = 0;
        let insertBatch = [];

        for (let i = 0; i < data.data.hosts.length; i++) {
          count++;
            console.log(count)
          // if we've already scanned before, do something else.
                let oldHost = prevHosts.filter((e) => e.publickeystring === data.data.hosts[i].publickeystring)
                console.log(oldHost)

                // if is a new host

                // cam you paused here.
                /* 
                *  what you were doing was this.
                    basically, we need to put each of these into their own functions
                    check port
                    ip/dns resolver
                     and geolocation and xm check and date/time announced
                     they all go into own functions

                     if device is a new, do all the checks on the host
                     if not, run only the IP comparison
                     and run port checks. 
                     no need to do geolocation unless ip has changed.
                     we will need an updated_at column as well

                * 
                * 
                */
          //if (oldHost.length < 1) { }
          // async function processNewHost(host) {}
          // make IP easier to read, split from netaddress:port.
          let ip = data.data.hosts[i].netaddress.split(":")[0];
          data.data.hosts[i].ip = ip; // add to host object
          verbose(`locating ${ip}`);
          if (ip.match(ipRegex) == null) {
            // if ip is not a number
            verbose(
              `${ip} is not a number and we need to reverse the DNS on it..`
            );
            data.data.hosts[i].hostname = ip; // add to host object
            try {
              await lookUpDNS(ip) // lookup reverse dns
                .then((dns) => {
                  verbose("resolved to the ip below");
                  data.data.hosts[i].ip = dns; // add to host object as ip, replacing previously set.
                  ip = dns;
                  verbose(dns);
                  verbose("end of dns lookup");
                })
                .catch((err) => {
                  verbose(err);
                });
            } catch (e) {
              verbose(e);
            }
          }

          // begin port checking block ;
          verbose("initiate port check");
          let ports = []; // array for ports to check
          let siamux =
            data.data.hosts[i].siamuxport != ""
              ? data.data.hosts[i].siamuxport
              : 4283;
          let relayerPort =
            data.data.hosts[i].relayerport != ""
              ? data.data.hosts[i].relayerport
              : 4285;
          ports.push(siamux);
          ports.push(relayerPort);
          ports.push(parseInt(data.data.hosts[i].netaddress.split(":")[1]));
          verbose(`Ports on host ${ports}`); // make sure we have a list of ports in logs

          let closedPorts = []; // placeholder for closed ports in loop below
          if (ports.length > 1) {
            // make sure we got ports to check..
            verbose("running port scanner");
            for (let a = 0; a < ports.length; a++) {
              try {
                await isPortReachable(parseInt(ports[a]), { host: ip }) // can we reach their ports?
                  .then((status) => {
                    verbose(status);
                    if (!status) {
                      closedPorts.push(ports[a]); // push every closed port to closedPorts array
                    }
                  })
                  .catch((error) => {
                    verbose(error);
                  });
              } catch (error) {
                verbose(error);
              }
            } // loop ends here
          } // if ends here
          verbose(`closed ports ${closedPorts}`);
          data.data.hosts[i].closedPorts = closedPorts; // add to host object, even if empty.

          //begin geolocation block;
          verbose(`checking ${ip} geolocation`);
          let geoLocation = await geolocateIp(ip); // get ip location
          verbose(geoLocation);
          data.data.hosts[i].geoLocation = geoLocation; // add to host object

          // check if xm (Api)
          let XM = await checkXM(data.data.hosts[i].publickeystring);
          verbose(`is XAMiner: ${XM}`);
          data.data.hosts[i].xm = XM;

          // get block timestamp
          let firstseen_timestamp = await getBlockDateTime(
            data.data.hosts[i].firstseen
          );
          verbose(
            `device was first seen ${new Date(firstseen_timestamp * 1000)}`
          );
          data.data.hosts[i].firstseen_timestamp = firstseen_timestamp;

          // do sql insert here, make it await too cause wtf not.
          processTx(data.data.hosts[i]).then((whenDone) => {
            // add to the insertBatch array.
            //console.log(whenDone)
            insertBatch.push(whenDone);
          });
          verbose("cycle completed");

          //console.log(count);
          if (count == data.data.hosts.length) {
            // fire this at the end of the loop.
            verbose("reached end of loop, writing");
            let insertEm = await db.batchInsert("hosts", insertBatch);
            end = +new Date();
            writeFile("hosts.json", JSON.stringify(data.data), (err) => {
              if (err) throw err;
              verbose("wrote hosts to local file");
              console.log(`everything started at ${start}`);
              console.log(`and it ended at ${end}`);
            });
          }
        }
      })
      .catch((error) => {
        verbose("hit an erroar");
        verbose(error);
      });
}

async function lookUpDNS(ip) {
    const dnsOptions = {
        family: 4,
        hints: dns.ADDRCONFIG | dns.V4MAPPED,
    }

    return new Promise((resolve, reject) => {
        dns.lookup(ip, dnsOptions, (err, address) => {
            if (err) reject(err);
            resolve(address)
        })
    })
}

async function checkXM(pk) {
    return new Promise((resolve, reject) => {
        axios.get(`https://api.scpri.me/api/rest/xm/${pk}`)
        .then((data) => {
            if (data.data.network_appliances.length > 0) {
                resolve(true)
            } else {
                resolve(false)
            }
        })
        .catch((error) =>{
            console.log(error)
            reject(error)
        })
    })
}

async function verbose(data) {
    if (DEBUG_PLS) {
        console.log(data)
    }
}

function createHostsTable() {
    return db.schema
        .createTable('hosts', function (table) {
            table.increments('id').primary(); // id
            table.boolean('acceptingcontracts') // is accepting contracts?
            table.string('maxdownloadbatchsize')
            table.integer('maxduration')
            table.string('maxrevisebatchsize')
            table.string('netaddress');
            table.string('remainingstorage');
            table.string('sectorsize')
            table.string('totalstorage')
            table.string('unlockhash')
            table.integer('windowsize')
            table.string('collateral');
            table.string('maxcollateral');
            table.string('baserpcprice');
            table.string('contractprice');
            table.string('downloadbandwidthprice');
            table.string('sectoraccessprice');
            table.string('keyvaluesetprice');
            table.string('keyvaluegetprice');
            table.string('keyvaluedeleteprice');
            table.string('uploadbandwidthprice');
            table.string('ephemeralaccountexpiry');
            table.string('maxephemeralaccountbalance');
            table.string('revisionnumber');
            table.string('version');
            table.string('siamuxport');
            table.string('relayerport');
            table.string('firstseen');
            table.string('firstseen_timestamp');
            table.string('historicdowntime');
            table.string('historicuptime');
            table.json('scanhistory');
            table.string('historicfailedinteractions');
            table.string('historicsuccessfulinteractions');
            table.string('recentfailedinteractions');
            table.string('recentsuccessfulinteractions');
            table.string('lasthistoricupdate');
            table.string('ipnets');
            table.string('lastipnetchange');
            table.json('publickey');
            table.string('filtered');
            table.string('publickeystring');
            table.string('ip');
            table.string('hostname');
            table.string('closedPorts');
            table.json('geoLocation');
            table.boolean('xm')
        })
        .then((created) => {
            console.log(created)
        })
}

async function startUp() {  // the main function ran when script is started
    let hasHostsTable = await db.schema.hasTable("hosts"); // check to see if hosts table exists
    if (hasHostsTable == false) {  // if not
        createHostsTable().then((woo) => { // create our tables
            verbose('tables made and we good to roll')
            scanHostDB()
        })
    } else { // if it does
        scanHostDB()
        console.log('idling')
        
    }
}

startUp(); // run the damn thing when you launch.


async function addHost(host) {
    return new Promise((resolve, reject) => {
        db('hosts')
            .select('*')
            .where('publickeystring', host.publickeystring)
            .then((results) => {
                if (results.length === 0) {
                    // not found, insert fresh
                db('hosts').insert({
                        acceptingcontracts: host.acceptingcontracts,
                        maxdownloadbatchsize: host.maxdownloadbatchsize,
                        maxduration: host.maxduration,
                        maxrevisebatchsize: host.maxrevisebatchsize,
                        netaddress: host.netaddress,
                        remainingstorage: host.remainingstorage,
                        sectorsize: host.sectorsize,
                        totalstorage: host.totalstorage,
                        unlockhash: host.unlockhash,
                        windowsize: host.windowsize,
                        collateral: host.collateral,
                        maxcollateral: host.maxcollateral,
                        baserpcprice: host.baserpcprice,
                        contractprice: host.contractprice,
                        downloadbandwidthprice: host.downloadbandwidthprice,
                        sectoraccessprice: host.sectoraccessprice,
                        keyvaluesetprice: host.keyvaluesetprice,
                        keyvaluegetprice: host.keyvaluegetprice,
                        keyvaluedeleteprice: host.keyvaluedeleteprice,
                        uploadbandwidthprice: host.uploadbandwidthprice,
                        ephemeralaccountexpiry: host.ephemeralaccountexpiry,
                        maxephemeralaccountbalance: host.maxephemeralaccountbalance,
                        revisionnumber: host.revisionnumber,
                        version: host.version,
                        siamuxport: host.siamuxport,
                        relayerport: host.relayerport,
                        firstseen: host.firstseen,
                        historicdowntime: host.historicdowntime,
                        historicuptime: host.historicuptime,
                        scanhistory: JSON.stringify(host.scanhistory),
                        historicfailedinteractions: host.historicfailedinteractions,
                        historicsuccessfulinteractions: host.historicsuccessfulinteractions,
                        recentfailedinteractions: host.recentfailedinteractions,
                        recentsuccessfulinteractions: host.recentsuccessfulinteractions,
                        lasthistoricupdate: host.lasthistoricupdate,
                        ipnets: host.ipnets,
                        lastipnetchange: host.lastipnetchange,
                        publickey: JSON.stringify(host.publickey),
                        filtered: host.filtered,
                        publickeystring: host.publickeystring,
                        ip: host.ip,
                        hostname: host.hostname,
                        closedPorts: host.closedPorts,
                        geoLocation: JSON.stringify(host.geoLocation),
                        xm: host.xm,
                })
                .then((results) => { resolve('ok')})
                .catch(error => reject(error))
                } else {
                    // do update
                    db('hosts').where('publickeystring', host.publickeystring).update({
                                    acceptingcontracts: host.acceptingcontracts,
                                    maxdownloadbatchsize: host.maxdownloadbatchsize,
                                    maxduration: host.maxduration,
                                    maxrevisebatchsize: host.maxrevisebatchsize,
                                    netaddress: host.netaddress,
                                    remainingstorage: host.remainingstorage,
                                    sectorsize: host.sectorsize,
                                    totalstorage: host.totalstorage,
                                    unlockhash: host.unlockhash,
                                    windowsize: host.windowsize,
                                    collateral: host.collateral,
                                    maxcollateral: host.maxcollateral,
                                    baserpcprice: host.baserpcprice,
                                    contractprice: host.contractprice,
                                    downloadbandwidthprice: host.downloadbandwidthprice,
                                    sectoraccessprice: host.sectoraccessprice,
                                    keyvaluesetprice: host.keyvaluesetprice,
                                    keyvaluegetprice: host.keyvaluegetprice,
                                    keyvaluedeleteprice: host.keyvaluedeleteprice,
                                    uploadbandwidthprice: host.uploadbandwidthprice,
                                    ephemeralaccountexpiry: host.ephemeralaccountexpiry,
                                    maxephemeralaccountbalance: host.maxephemeralaccountbalance,
                                    revisionnumber: host.revisionnumber,
                                    version: host.version,
                                    siamuxport: host.siamuxport,
                                    relayerport: host.relayerport,
                                    firstseen: host.firstseen,
                                    historicdowntime: host.historicdowntime,
                                    historicuptime: host.historicuptime,
                                    scanhistory: JSON.stringify(host.scanhistory),
                                    historicfailedinteractions: host.historicfailedinteractions,
                                    historicsuccessfulinteractions: host.historicsuccessfulinteractions,
                                    recentfailedinteractions: host.recentfailedinteractions,
                                    recentsuccessfulinteractions: host.recentsuccessfulinteractions,
                                    lasthistoricupdate: host.lasthistoricupdate,
                                    ipnets: host.ipnets,
                                    lastipnetchange: host.lastipnetchange,
                                    publickey: JSON.stringify(host.publickey),
                                    filtered: host.filtered,
                                    publickeystring: host.publickeystring,
                                    ip: host.ip,
                                    hostname: host.hostname,
                                    closedPorts: host.closedPorts,
                                    geoLocation: JSON.stringify(host.geoLocation),
                                    xm: host.xm,
                                }).then((results) => {
                                    resolve('Updated')
                                }).catch((err) => {
                                    reject(err);
                                })
                }
            })
            .catch((error) => {
                console.log(error);
        })
    })
}

async function processTx(host) {
    return new Promise((resolve, reject) => {
    let newHost = {
        acceptingcontracts: host.acceptingcontracts,
        maxdownloadbatchsize: host.maxdownloadbatchsize,
        maxduration: host.maxduration,
        maxrevisebatchsize: host.maxrevisebatchsize,
        netaddress: host.netaddress,
        remainingstorage: host.remainingstorage,
        sectorsize: host.sectorsize,
        totalstorage: host.totalstorage,
        unlockhash: host.unlockhash,
        windowsize: host.windowsize,
        collateral: host.collateral,
        maxcollateral: host.maxcollateral,
        baserpcprice: host.baserpcprice,
        contractprice: host.contractprice,
        downloadbandwidthprice: host.downloadbandwidthprice,
        sectoraccessprice: host.sectoraccessprice,
        keyvaluesetprice: host.keyvaluesetprice,
        keyvaluegetprice: host.keyvaluegetprice,
        keyvaluedeleteprice: host.keyvaluedeleteprice,
        uploadbandwidthprice: host.uploadbandwidthprice,
        ephemeralaccountexpiry: host.ephemeralaccountexpiry,
        maxephemeralaccountbalance: host.maxephemeralaccountbalance,
        revisionnumber: host.revisionnumber,
        version: host.version,
        siamuxport: host.siamuxport,
        relayerport: host.relayerport,
        firstseen: host.firstseen,
        firstseen_timestamp: host.firstseen_timestamp,
        historicdowntime: host.historicdowntime,
        historicuptime: host.historicuptime,
        scanhistory: JSON.stringify(host.scanhistory),
        historicfailedinteractions: host.historicfailedinteractions,
        historicsuccessfulinteractions: host.historicsuccessfulinteractions,
        recentfailedinteractions: host.recentfailedinteractions,
        recentsuccessfulinteractions: host.recentsuccessfulinteractions,
        lasthistoricupdate: host.lasthistoricupdate,
        ipnets: host.ipnets,
        lastipnetchange: host.lastipnetchange,
        publickey: JSON.stringify(host.publickey),
        filtered: host.filtered,
        publickeystring: host.publickeystring,
        ip: host.ip,
        hostname: host.hostname,
        closedPorts: host.closedPorts,
        geoLocation: JSON.stringify(host.geoLocation),
        xm: host.xm
    }
    resolve(newHost)
    })
}

async function getBlockDateTime(height) {
    //console.log('getting block date time')
    return new Promise((resolve, reject) => {
        axios.get(`http://localhost:4280/consensus/blocks?height=${height}`, 
        {
            headers: {
            "User-Agent": "ScPrime-Agent"
        }})
        .then((data) =>{
            //console.log(data)
            resolve(data.data.timestamp)
        })
        .catch((error) =>{
            reject(error)
        })
    })
}
const spawn = require('child_process').spawn;
const AdmZip = require('adm-zip');
const dns = require('dns');
const _ = require('lodash');
const util = require('util');
const db = require('../../db');

require('util.promisify').shim(); // for nodejs < 8

exports.after_modification = (req) => (
    console.log("trigger proxy_transp after_modification"),
    db.collection(req.params.db, req.params.collection).then(collection => (
        db.find(collection, {})
    )).then(rules => simplify_rules(rules)).then(srules => (
        allIps(srules).then(ips => (      
            popen(toZip(srules, ips), 'tee', ['/tmp/z.zip'])
        ))
    ))
);

// we don't keep comments/who/date 
const simplify_rules = rules => (
    rules.map(rule => ({
        id: rule.id,
        srcs: rule.srcs.map(v => v.val),
        dests: rule.dests.map(v => v.val),
    }))
);

const lookupAsync = util.promisify(dns.lookup);

// return something like { hostname: "cas1-dev", ips: "193.55.96.113 2001:660:3305::113" }
const get_ips = hostname => (
    Promise.all([4, 6].map(family => (
        lookupAsync(hostname, { family })
    ))).then(l => ({ hostname, ips: l.join(' ') }))
);

// return a map { "cas1-dev": { ..., ips: "193.55.96.113 2001:660:3305::113" } }
const allIps = srules => (
    Promise.all(_.flatMap(srules, rule => rule.srcs).map(get_ips))
);

const toZip = (srules, ips) => {
    
    let zip = new AdmZip();
    const addFile = (file, lines) => (
        //console.log(file, lines),
        zip.addFile(file, new Buffer(_.concat(
            "#################################################################",
            "##                                                             ##",
            "##  ATTENTION, genere par https://proxy-transp.univ-paris1.fr  ##",
            "##                                                             ##",
            "#################################################################",
            lines
        ).map(s => s + "\n").join('')))
    );

    addFile("acl-src.conf", ips.map(e => "acl " + e.hostname + " src " + e.ips));

    addFile("acl-access.conf", (
        _.flatMap(srules, rule => rule.srcs.map(src => "http_access allow http_" + rule.id + " " + src))
    ));

    addFile("acl-dst.conf", _.concat(
        "# for HTTPS (splice)",
        srules.map(rule => 'acl splice_' + rule.id + ' ssl::server_name "/etc/squid/conf.d/' + rule.id + '_allowed-domains.list"'),
        "# for HTTP (classic http_access rule)",
        srules.map(rule => 'acl http_' + rule.id + ' dstdomain "/etc/squid/conf.d/' + rule.id + '_allowed-domains.list"')
    ));

    addFile("acl-bump.conf", _.concat(
        "# here we're splicing trusted connections to servers which names match our whitelists",
        _.flatMap(srules, rule => rule.srcs.map(src => "ssl_bump splice step2 splice_" + rule.id + " " + src)),
        '', "# at step 2 we're peeking at server certificate (needed if no SNI found at step1)",
        _.flatMap(srules, rule => rule.srcs.map(src => "ssl_bump peek step2 splice_" + rule.id + " " + src)),
        '', "# here we're splicing trusted connections not identified before because there were no info in client's TLS-request (but only if info were found in server certificate)",
        _.flatMap(srules, rule => rule.srcs.map(src => "ssl_bump splice step3 splice_" + rule.id + " " + src))
    ));

    srules.forEach(rule => {
        addFile('conf.d/' + rule.id + '_allowed-domains.list', rule.dests);
    });

    return zip.toBuffer();
}

function popen(inText, cmd, params) {
    let p = spawn(cmd, params);
    p.stdin.write(inText);
    p.stdin.end();

    return new Promise((resolve, reject) => {
        let output = '';
        let get_ouput = data => { output += data; };
        
        p.stdout.on('data', get_ouput);
        p.stderr.on('data', get_ouput);
        p.on('error', event => {
            reject(event);
        });
        p.on('close', code => {
            if (code === 0) resolve(output); else reject(output);
        });
    });
}
